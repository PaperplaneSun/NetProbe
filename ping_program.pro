# MLSgen.pro
TEMPLATE = app
QT += core gui

# Sources
SOURCES += ping_echo.cpp \
           mls.cpp \
           aes.c  # 如果你的项目使用了 C 文件，记得添加到这里

# Headers
HEADERS += mls.h \
           aes.h

# Include path (if necessary)
INCLUDEPATH += .

# For Qt4 compatibility, uncomment the following if you're using Qt4
# CONFIG += qt4

# If you need additional libraries
# LIBS += -L/path/to/libs -lSomeLibrary


