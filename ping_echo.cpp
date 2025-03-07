#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <sys/select.h>
#include <sys/stat.h>
#include "mls.h"
#include <vector>

#define MISSING_VALUE -1.0
#define ICMP_ECHO_REQUEST 8
#define ICMP_ECHO_REPLY 0
#define MAX_PACKETS 100000
#define MAX_FREQ 1000         // 最大频率1KHz
#define MIN_PAYLOAD_SIZE 56   // 最小载荷长度 56字节
#define MAX_PAYLOAD_SIZE 1472 // 最大载荷长度 1472字节
#define MODE_FILE 1           // 模式1：从文件读取序列
#define MODE_RANDOM 2         // 模式2：生成随机MLS序列

#define MAX_PATH_LENGTH 1024
#define MAX_COMMON_PREFIX_LENGTH 200

// ICMP头部结构
typedef struct
{
    unsigned char type;
    unsigned char code;
    unsigned short checksum;
    unsigned short id;
    unsigned short seq;
} ICMP_HEADER;

// 记录结构
typedef struct
{
    uint32_t sequence;
    double send_time;
    double receive_time;
    double rtt;
    double send_rate;
    double send_interval;
    int is_received;
    int payload_size;
} PING_RECORD;

// 全局变量
PING_RECORD *record_buffer = NULL;
int *sequence = NULL;
int total_packets;
int running = 1;
int sockRaw;
FILE *log_file;
int target_triggered = 0;
int is_active = 0;
int mode;
int received_count = 0;
struct sockaddr_in dest;

// 递归创建多级目录
void ensure_directory_exists(const char *path)
{
    char temp_path[1024];
    struct stat st;

    // 拷贝路径，避免修改原路径
    strncpy(temp_path, path, sizeof(temp_path) - 1);
    temp_path[sizeof(temp_path) - 1] = '\0';

    // 如果路径以 '/' 结尾，移除它（避免空目录名）
    size_t len = strlen(temp_path);
    if (len > 0 && temp_path[len - 1] == '/')
    {
        temp_path[len - 1] = '\0';
    }

    // 逐层检查并创建目录
    for (char *p = temp_path + 1; *p; ++p)
    {
        if (*p == '/')
        {
            *p = '\0'; // 暂时终止路径
            if (stat(temp_path, &st) == -1)
            { // 检查目录是否存在
                if (mkdir(temp_path, 0777) == -1 && errno != EEXIST)
                { // 创建目录
                    perror("Failed to create directory");
                    exit(EXIT_FAILURE);
                }
            }
            *p = '/'; // 恢复路径
        }
    }

    // 创建最后一层目录（完整路径）
    if (stat(temp_path, &st) == -1)
    {
        if (mkdir(temp_path, 0777) == -1 && errno != EEXIST)
        {
            perror("Failed to create directory");
            exit(EXIT_FAILURE);
        }
    }
}

void build_common_prefix(char *buffer, size_t size, unsigned int sequence, unsigned int packets,
                         const char *signal_file, int freq, const char *host_label)
{
    snprintf(buffer, size, "%u_%u_%s_%d_%s", sequence, packets, signal_file, freq, host_label);
}

// 计算校验和
unsigned short calculate_checksum(unsigned short *buffer, int size)
{
    unsigned long cksum = 0;
    while (size > 1)
    {
        cksum += *buffer++;
        size -= sizeof(unsigned short);
    }
    if (size)
    {
        cksum += *(unsigned char *)buffer;
    }
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);
    return (unsigned short)(~cksum);
}

// 精确等待
void SpinWait(struct timespec *last_time, double target_us)
{
    struct timespec now;
    double elapsed_us;
    do
    {
        clock_gettime(CLOCK_MONOTONIC, &now);
        elapsed_us = (now.tv_sec - last_time->tv_sec) * 1e6 +
                     (now.tv_nsec - last_time->tv_nsec) / 1e3;
    } while (elapsed_us < target_us);
}

// 读取或生成序列
int *generate_sequence(int total_packets, const char *filename, int mode)
{
    int *sequence = (int *)malloc(total_packets * sizeof(int));
    if (!sequence)
    {
        perror("Failed to allocate memory for sequence");
        exit(EXIT_FAILURE);
    }

    if (mode == MODE_FILE)
    {
        FILE *file = fopen(filename, "r");
        if (!file)
        {
            fprintf(stderr, "Failed to open sequence file: %s\n", filename);
            free(sequence);
            exit(EXIT_FAILURE);
        }

        int i = 0;
        while (i < total_packets && fscanf(file, "%d", &sequence[i]) == 1)
        {
            if (sequence[i] != 0 && sequence[i] != 1)
            {
                fprintf(stderr, "Invalid value in sequence file at line %d\n", i + 1);
                fclose(file);
                free(sequence);
                exit(EXIT_FAILURE);
            }
            i++;
        }

        if (i < total_packets)
        {
            fprintf(stderr, "Warning: sequence file contains fewer entries than required (%d/%d)\n", i, total_packets);
            for (; i < total_packets; i++)
            {
                sequence[i] = 0;
            }
        }

        fclose(file);
    }
    else
    {
        // srand((unsigned int)time(NULL));
        int nbits;
        uint32_t initseed;

        // 使用 sscanf 从字符串中提取 nbits 和 initseed
        if (sscanf(filename, "n%d s%u", &nbits, &initseed) == 2)
        {
            printf("nbits: %d\n", nbits);
            printf("initSeed: %u\n", initseed);
        }
        else
        {
            printf("Failed to parse input string.\n");
        }
        mls mls_aes(nbits, false);
        vector<bool> mls_seq = mls_aes.get_seq(initseed);
        for (int i = 0; i < total_packets; i++)
        {
            sequence[i] = mls_seq[i];
        }
    }

    return sequence;
}

int triggered = 0;

// 接收线程，用 recvfrom 接收数据包
void *ReceiverThread(void *param)
{
    printf("Receiver thread started\n");

    char recv_buf[MAX_PAYLOAD_SIZE + sizeof(struct iphdr) + sizeof(ICMP_HEADER)];
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    struct iphdr *ip_header;
    ICMP_HEADER *icmp_header;
    struct timespec recv_time, last_valid_packet_time;

    fd_set read_fds;
    struct timeval timeout;

    while (running)
    {

        // 设置超时时间为3秒
        timeout.tv_sec = triggered ? 3 : 0;
        timeout.tv_usec = triggered ? 0 : 100;

        // 清空读集合
        FD_ZERO(&read_fds);
        FD_SET(sockRaw, &read_fds); // 将 sockRaw 加入监听集合

        // 使用 select 来监听 socket 是否有数据
        int ret = select(sockRaw + 1, &read_fds, NULL, NULL, &timeout);

        if (ret == -1)
        {
            perror("select failed");
            continue; // 如果 select 失败，继续循环
        }

        if (ret == 0)
        {
            // 超时处理
            struct timespec current_time;
            clock_gettime(CLOCK_MONOTONIC, &current_time);

            // 检查是否超过 3 秒未收到目标包
            double elapsed_time = (current_time.tv_sec - last_valid_packet_time.tv_sec) +
                                  (current_time.tv_nsec - last_valid_packet_time.tv_nsec) / 1e9;

            if (triggered && elapsed_time >= 3.0)
            {
                printf("No relevant packet received within 3 seconds, exiting receiver thread...\n");
                running = 0; // 设置 running 为 0 来结束循环
                break;
            }

            if (!triggered)
            {
                printf("No packet received within 100 microseconds, waiting to trigger...\n");
            }

            continue;
        }

        // 如果有数据包准备好，接收数据
        if (FD_ISSET(sockRaw, &read_fds))
        {
            int recv_size = recvfrom(sockRaw, recv_buf, sizeof(recv_buf), 0,
                                     (struct sockaddr *)&from, &from_len);
            if (recv_size > 0)
            {
                clock_gettime(CLOCK_MONOTONIC, &recv_time);

                ip_header = (struct iphdr *)recv_buf;
                int ip_header_len = ip_header->ihl * 4;
                icmp_header = (ICMP_HEADER *)(recv_buf + ip_header_len);
                // 打印源 IP 和目标 IP
                char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &ip_header->saddr, src_ip, sizeof(src_ip)); // 源 IP
                inet_ntop(AF_INET, &ip_header->daddr, dst_ip, sizeof(dst_ip)); // 目标 IP

                printf("Received packet from: %s, Destination: %s\n", src_ip, dst_ip);

                // 判断目标 IP 是否匹配
                if (ip_header->saddr != dest.sin_addr.s_addr)
                {
                    printf("Packet ignored: source IP does not match target IP.\n");
                    // 超时处理
                    struct timespec current_time;
                    clock_gettime(CLOCK_MONOTONIC, &current_time);

                    // 检查是否超过 3 秒未收到目标包
                    double elapsed_time = (current_time.tv_sec - last_valid_packet_time.tv_sec) +
                                          (current_time.tv_nsec - last_valid_packet_time.tv_nsec) / 1e9;

                    if (triggered && elapsed_time >= 3.0)
                    {
                        printf("No relevant packet received within 3 seconds, exiting receiver thread...\n");
                        running = 0; // 设置 running 为 0 来结束循环
                        break;
                    }
                    continue; // 跳过非目标 IP 的数据包
                }

                printf("Received packet info: icmp_header->id - %d getpid - %d\n", ntohs(icmp_header->id), getpid() & 0xFFFF);

                // 如果是监听模式，检查是否接收到触发的 ICMP 请求
                if (icmp_header->type == ICMP_ECHO_REQUEST && !is_active && !target_triggered)
                {
                    clock_gettime(CLOCK_MONOTONIC, &last_valid_packet_time);
                    target_triggered = 1;
                    triggered = 1;
                    printf("Trigger received from ICMP ECHO REQUEST.\n");
                    continue;
                }

                // 检查是否是 ICMP 回复包
                if (icmp_header->type == ICMP_ECHO_REPLY && ntohs(icmp_header->id) == (getpid() & 0xFFFF))
                {
                    int seq = ntohs(icmp_header->seq);
                    if (seq < total_packets && !record_buffer[seq].is_received)
                    {
                        clock_gettime(CLOCK_MONOTONIC, &last_valid_packet_time);
                        record_buffer[seq].is_received = 1;
                        record_buffer[seq].receive_time = recv_time.tv_sec + recv_time.tv_nsec / 1e9;
                        record_buffer[seq].rtt = (record_buffer[seq].receive_time - record_buffer[seq].send_time) * 1e6;
                        printf("Received packet seq=%d, RTT=%.3f us\n", seq, record_buffer[seq].rtt);
                        received_count++;
                    }
                }

                // 超时处理
                struct timespec current_time;
                clock_gettime(CLOCK_MONOTONIC, &current_time);

                // 检查是否超过 3 秒未收到目标包
                double elapsed_time = (current_time.tv_sec - last_valid_packet_time.tv_sec) +
                                      (current_time.tv_nsec - last_valid_packet_time.tv_nsec) / 1e9;

                if (triggered && elapsed_time >= 3.0)
                {
                    printf("No relevant packet received within 3 seconds, exiting receiver thread...\n");
                    running = 0; // 设置 running 为 0 来结束循环
                    break;
                }
            }
        }
    }
    return NULL;
}

char *get_current_time()
{
    char *time_string = (char *)malloc(100 * sizeof(char)); // 动态分配内存
    if (time_string == NULL)
    {
        return NULL; // 内存分配失败
    }
    time_t current_time;
    struct tm *time_info;

    // 获取当前系统时间
    time(&current_time);

    // 将时间转换为本地时间
    time_info = localtime(&current_time);

    // 使用 strftime 格式化时间
    strftime(time_string, 100, "%Y-%m-%d %H:%M:%S", time_info);

    return time_string;
}

int main(int argc, char *argv[])
{
    char *program_start_time = get_current_time();
    if (argc != 8 || (strcmp(argv[7], "--active") != 0 && strcmp(argv[7], "--listen") != 0))
    {
        printf("Usage: %s <destination_ip> <number_of_packets> <frequency_hz> <mode (1=file, 2=random)> <sequence_file> <host_label> --active|--listen\n", argv[0]);
        return -1;
    }

    mode = atoi(argv[4]);
    sequence = generate_sequence(atoi(argv[2]), argv[5], mode);

    if (strcmp(argv[7], "--active") == 0)
    {
        is_active = 1;
        printf("Active mode enabled.\n");
    }
    else if (strcmp(argv[7], "--listen") == 0)
    {
        is_active = 0;
        printf("Listen mode enabled.\n");
    }
    else
    {
        fprintf(stderr, "Invalid option: %s\n", argv[7]);
        return -1;
    }

    triggered = (is_active == 1);
    sockRaw = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockRaw < 0)
    {
        perror("Failed to create raw socket");
        return -1;
    }

    // struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(argv[1]);

    total_packets = atoi(argv[2]);
    int send_freq = atoi(argv[3]);
    double target_interval_us = 1000000.0 / send_freq;

    record_buffer = (PING_RECORD *)calloc(total_packets, sizeof(PING_RECORD));

    pthread_t receiver_thread;
    pthread_create(&receiver_thread, NULL, ReceiverThread, NULL);

    // 等待触发信号（仅在监听模式下）
    if (!is_active)
    {
        printf("Listening for trigger ICMP Echo Request...\n");
        while (!target_triggered)
        {
            usleep(100); // 检查触发状态
        }
        printf("Trigger received, starting ICMP Echo Requests...\n");
    }

    struct timespec send_start_time, last_send;
    clock_gettime(CLOCK_MONOTONIC, &send_start_time);
    last_send = send_start_time;

    char *sending_start_time = get_current_time();
    int seq = 0;
    while (seq < total_packets)
    {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);

        record_buffer[seq].sequence = seq + 1;
        record_buffer[seq].send_time = now.tv_sec + now.tv_nsec / 1e9;
        record_buffer[seq].send_rate = send_freq;
        if (seq > 0)
        {
            record_buffer[seq].send_interval = (double)(now.tv_sec - last_send.tv_sec) * 1e6 + (now.tv_nsec - last_send.tv_nsec) / 1e3;
        }
        else
        {
            record_buffer[seq].send_interval = 0;
        }

        int payload_size = (sequence[seq] == 1) ? MAX_PAYLOAD_SIZE : MIN_PAYLOAD_SIZE;

        unsigned char icmp_packet[sizeof(ICMP_HEADER) + MAX_PAYLOAD_SIZE];
        memset(icmp_packet, 0, sizeof(ICMP_HEADER) + payload_size);
        ICMP_HEADER *icmp = (ICMP_HEADER *)icmp_packet;
        icmp->type = ICMP_ECHO_REQUEST;
        icmp->code = 0;
        icmp->id = htons(getpid() & 0xFFFF);
        icmp->seq = htons(seq);

        icmp->checksum = calculate_checksum((unsigned short *)icmp_packet, sizeof(ICMP_HEADER) + payload_size);

        if (sendto(sockRaw, icmp_packet, sizeof(ICMP_HEADER) + payload_size, 0,
                   (struct sockaddr *)&dest, sizeof(dest)) < 0)
        {
            perror("Send failed");
            continue;
        }

        record_buffer[seq].payload_size = payload_size;
        printf("sending seq : %d payload : %u icmp length : %lu \n", seq, payload_size, sizeof(ICMP_HEADER) + payload_size);
        seq++;

        last_send = now;
        SpinWait(&last_send, target_interval_us);
    }
    // 等待接收线程完成
    printf("Waiting for remaining responses...\n");
    // usleep(1000000);
    // running = 0;
    // printf("Stop waiting remaining responses...\n");
    pthread_join(receiver_thread, NULL);

    // 计算总发送时间（单位：秒）
    double total_send_time = (double)(last_send.tv_sec - send_start_time.tv_sec) + (double)(last_send.tv_nsec - send_start_time.tv_nsec) / 1000000000.0;

    // 打印发送详细信息
    printf("\nTransmission details:\n");
    printf("Start time: %.6f s\n", (double)send_start_time.tv_sec + (double)send_start_time.tv_nsec / 1000000000.0);
    printf("End time: %.6f s\n", (double)last_send.tv_sec + (double)last_send.tv_nsec / 1000000000.0);
    printf("Total time: %.6f s\n", total_send_time);
    printf("Timer frequency: %d Hz\n", send_freq);

    // 计算平均发送速率
    if (total_send_time > 0)
    {
        printf("Average sending rate: %.2f Hz\n", (double)total_packets / total_send_time);
    }
    else
    {
        printf("Error: Invalid total send time\n");
    }
    // 统计接收情况
    int received_count = 0;
    for (int i = 0; i < total_packets; i++)
    {
        if (record_buffer[i].is_received)
        {
            received_count++;
        }
    }
    printf("Received %d out of %d packets (%.1f%%)\n",
           received_count, total_packets, 100.0 * received_count / total_packets);

    // 提取 host_label
    const char *host_label = argv[6];

    // 读取实验序列
    const char *sequence_counter_path = "setup/sequence_counter.txt";
    FILE *seq_file = fopen(sequence_counter_path, "r+");
    if (!seq_file)
    {
        perror("Failed to open sequence_counter.txt");
        exit(EXIT_FAILURE);
    }

    unsigned int experiment_sequence;
    if (fscanf(seq_file, "%u", &experiment_sequence) != 1)
    {
        perror("Failed to read sequence number");
        fclose(seq_file);
        exit(EXIT_FAILURE);
    }
    rewind(seq_file);
    fprintf(seq_file, "%u", experiment_sequence + 1);
    fclose(seq_file);

    // 提取 signal_file 名称
    char *signal_file = strrchr(argv[5], '/');
    if (signal_file)
    {
        signal_file++;
    }
    else
    {
        signal_file = argv[5];
    }

    char *ext = strrchr(signal_file, '.');
    if (ext)
    {
        *ext = '\0';
    }

    char data_dir[MAX_PATH_LENGTH];
    char log_file_path[MAX_PATH_LENGTH];
    char xdata_path[MAX_PATH_LENGTH];
    char ydata_path[MAX_PATH_LENGTH];
    char common_prefix[MAX_COMMON_PREFIX_LENGTH];

    // 构造 common_prefix
    snprintf(common_prefix, sizeof(common_prefix), "%u_%u_%s_%d_%s",
             experiment_sequence, total_packets, signal_file, send_freq, host_label);

    if (strlen(common_prefix) >= MAX_COMMON_PREFIX_LENGTH)
    {
        fprintf(stderr, "Error: common_prefix exceeds the allowed length\n");
        exit(EXIT_FAILURE);
    }

    // 构造路径
    snprintf(data_dir, sizeof(data_dir), "data/%s", common_prefix);
    ensure_directory_exists(data_dir);

    // 创建并写入统计信息到 JSON 文件
    char stats_file_path[MAX_PATH_LENGTH];

    // 构造路径

    if (snprintf(stats_file_path, sizeof(stats_file_path), "%s/stats.json", data_dir) >= sizeof(stats_file_path))
    {
        fprintf(stderr, "Error: stats_file_path exceeds buffer size\n");
        exit(EXIT_FAILURE);
    }

    // 打开文件并写入统计信息
    FILE *stats_file = fopen(stats_file_path, "w");
    if (stats_file)
    {
        // 写入 JSON 格式的统计信息
        fprintf(stats_file, "{\n");
        fprintf(stats_file, "  \"experiment_sequence\": %u,\n", experiment_sequence);
        fprintf(stats_file, "  \"start_time\": %.6f,\n",
                (double)send_start_time.tv_sec + (double)send_start_time.tv_nsec / 1000000000.0);
        fprintf(stats_file, "  \"end_time\": %.6f,\n",
                (double)last_send.tv_sec + (double)last_send.tv_nsec / 1000000000.0);
        fprintf(stats_file, "  \"total_time\": %.6f,\n", total_send_time);
        fprintf(stats_file, "  \"timer_frequency\": %d,\n", send_freq);
        fprintf(stats_file, "  \"average_sending_rate\": %.2f,\n",
                (total_send_time > 0) ? (double)total_packets / total_send_time : 0.0);
        fprintf(stats_file, "  \"signal_source_mode\": %d,\n", mode);
        fprintf(stats_file, "  \"signal_source\": \"%s\",\n", argv[5]);
        fprintf(stats_file, "  \"received_count\": %d,\n", received_count);
        fprintf(stats_file, "  \"total_packets\": %d,\n", total_packets);
        fprintf(stats_file, "  \"received_percentage\": %.1f,\n",
                100.0 * received_count / total_packets);
        fprintf(stats_file, "  \"program start time\": \"%s\",\n", program_start_time);
        free(program_start_time);
        fprintf(stats_file, "  \"sending start time\": \"%s\",\n", sending_start_time);
        free(sending_start_time);
        char *collecting_start_time = get_current_time();
        fprintf(stats_file, "  \"collecting start time\": \"%s\"\n", collecting_start_time);
        free(collecting_start_time);
        fprintf(stats_file, "}\n");

        fclose(stats_file);
    }
    else
    {
        perror("Failed to open stats.json");
        exit(EXIT_FAILURE);
    }

    if (snprintf(log_file_path, sizeof(log_file_path), "%s/log.csv", data_dir) >= sizeof(log_file_path))
    {
        fprintf(stderr, "Error: log_file_path exceeds buffer size\n");
        exit(EXIT_FAILURE);
    }

    if (snprintf(xdata_path, sizeof(xdata_path), "%s/%s_xdata.csv", data_dir, common_prefix) >= sizeof(xdata_path))
    {
        fprintf(stderr, "Error: xdata_path exceeds buffer size\n");
        exit(EXIT_FAILURE);
    }

    if (snprintf(ydata_path, sizeof(ydata_path), "%s/%s_ydata.csv", data_dir, common_prefix) >= sizeof(ydata_path))
    {
        fprintf(stderr, "Error: ydata_path exceeds buffer size\n");
        exit(EXIT_FAILURE);
    }

    int total_packets = atoi(argv[2]);

    FILE *log_file = fopen(log_file_path, "w");
    if (log_file)
    {
        fprintf(log_file, "Sequence,SendTime(s),ReceiveTime(s),RTT(us),SendRate(Hz),SendInterval(us),PayloadSize(bytes)\n");
        for (int i = 0; i < total_packets; i++)
        {
            fprintf(log_file, "%u,%.9f,%.9f,%.3f,%.2f,%.3f,%d\n",
                    record_buffer[i].sequence,
                    record_buffer[i].send_time,
                    record_buffer[i].is_received ? record_buffer[i].receive_time : MISSING_VALUE,
                    record_buffer[i].is_received ? record_buffer[i].rtt : MISSING_VALUE,
                    record_buffer[i].send_rate,
                    record_buffer[i].send_interval,
                    record_buffer[i].payload_size);
        }
        fclose(log_file);
    }

    // 写入 xdata.csv

    FILE *xdata_file = fopen(xdata_path, "w");
    if (xdata_file)
    {
        fprintf(xdata_file, "Sequence\n");
        for (int i = 0; i < total_packets; i++)
        {
            fprintf(xdata_file, "%.3f\n", (record_buffer[i].payload_size + 28 + 14) * 0.001);
        }
        fclose(xdata_file);
    }

    // 写入 ydata.csv

    FILE *ydata_file = fopen(ydata_path, "w");
    if (ydata_file)
    {
        fprintf(ydata_file, "RTT(us)\n");
        for (int i = 0; i < total_packets; i++)
        {
            fprintf(ydata_file, "%.3f\n",
                    record_buffer[i].is_received ? record_buffer[i].rtt : MISSING_VALUE);
        }
        fclose(ydata_file);
    }

    printf("Configuration complete. Data directory: %s\n", data_dir);

    printf("end logging...\n");

    free(sequence);
    free(record_buffer);
    close(sockRaw);
    return 0;
}
