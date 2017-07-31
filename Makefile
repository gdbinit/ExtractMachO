TARGET=extractmacho.dylib
LIBTARGET=ida
# 64bits settings
ifdef __EA64__
SWITCH64=-D__EA64__
TARGET=extractmacho64.dylib
LIBTARGET=ida64
endif

SDKPATH=CHANGME_AND_POINT_TO_THE_SDK_DIR
LIBRARYPATH=CHANGEME_AND_POINT_TO_THE_IDAQ.APP_MACOS_FOLDER
#SDKPATH=/Applications/IDA\ Pro\ 7.0/idasdk70
#LIBRARYPATH=/Applications/IDA\ Pro\ 7.0/ida.app/Contents/MacOS/
SRC=extractmacho.cpp validate.cpp extractors.cpp
OBJS=extractmacho.o validate.o extractors.o
CC=g++
LD=g++
CFLAGS=-D__IDP__ -D__PLUGIN__ -c -D__MAC__ $(SWITCH64) -I$(SDKPATH)/include $(SRC)
LDFLAGS=--shared $(OBJS) -L$(SDKPATH) -L$(SDKPATH)/bin -l$(LIBTARGET) -Wl -L$(LIBRARYPATH)

all:
	$(CC) $(CFLAGS)

	$(LD) $(LDFLAGS) -o $(TARGET)
