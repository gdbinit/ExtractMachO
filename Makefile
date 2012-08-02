EXTENSION=pmc
LIBTARGET=ida
# 64bits settings
ifdef __EA64__
SWITCH64=-D__EA64__
EXTENSION=pmc64
LIBTARGET=ida64
endif

SDKPATH=CHANGME_AND_POINT_TO_THE_SDK_DIR
LIBRARYPATH=CHANGEME_AND_POINT_TO_THE_IDAQ.APP_MACOS_FOLDER
#SDKPATH=/Applications/IDA\ Pro\ 6.3/idasdk63
#LIBRARYPATH=/Applications/IDA\ Pro\ 6.3/idaq.app/Contents/MacOS/
SRC=extractmacho.cpp validate.cpp extractors.cpp
OBJS=extractmacho.o validate.o extractors.o
CC=g++
LD=g++
# binary is always i386
CFLAGS=-arch i386 -D__IDP__ -D__PLUGIN__ -c -D__MAC__ $(SWITCH64) -I$(SDKPATH)/include $(SRC)
LDFLAGS=-arch i386 --shared $(OBJS) -L$(SDKPATH) -L$(SDKPATH)/bin -l$(LIBTARGET) --no-undefined -Wl -L$(LIBRARYPATH)

all:
	$(CC) $(CFLAGS)
	$(LD) $(LDFLAGS) -o extractmacho.$(EXTENSION)

