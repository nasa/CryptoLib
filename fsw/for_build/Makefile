#  Copyright (C) 2009 - 2017 National Aeronautics and Space Administration. All Foreign Rights are Reserved to the U.S. Government.
#
#   This software is provided "as is" without any warranty of any, kind either express, implied, or statutory, including, but not
#   limited to, any warranty that the software will conform to, specifications any implied warranties of merchantability, fitness
#   for a particular purpose, and freedom from infringement, and any warranty that the documentation will conform to the program, or
#   any warranty that the software will be error free.
#
#   In no event shall NASA be liable for any damages, including, but not limited to direct, indirect, special or consequential damages,
#   arising out of, resulting from, or in any way connected with the software or its documentation.  Whether or not based upon warranty,
#   contract, tort or otherwise, and whether or not loss was sustained from, or arose out of the results of, or use of, the software,
#   documentation or services provided hereunder
#
#   ITC Team
#   NASA IV&V
#   ivv-itc@lists.nasa.gov

###############################################################################
# File: CFS Application Makefile 
###############################################################################
#
# Subsystem produced by this makefile.
#
APPTARGET = crypto

# 
# Entry Point for task
# 
ENTRY_PT = crypto_Init 

#
# Object files required to build subsystem.
#
OBJS = itc_aes128.o
OBJS += itc_gcm128.o
OBJS += itc_cmac128.o
OBJS += crypto.o
OBJS += crypto_print.o

#
# Source files required to build subsystem; used to generate dependencies.
# As long as there are no assembly files this can be automated.
#
SOURCES = $(OBJS:.o=.c)


##
## Specify extra C Flags needed to build this subsystem
##
LOCAL_COPTS = -Wfatal-errors -Werror -Wall -Wextra -Wstrict-prototypes 


##
## EXEDIR is defined here, just in case it needs to be different for a custom
## build
##
EXEDIR=../exe

##
## Certain OSs and Application Loaders require the following option for
## Shared libraries. Currently only needed for vxWorks 5.5 and RTEMS.
## For each shared library that this app depends on, you need to have an
## entry like the following:
##  -R../tst_lib/tst_lib.elf
##
SHARED_LIB_LINK = -lgcrypt

########################################################################
# Should not have to change below this line, except for customized 
# Mission and cFE directory structures
########################################################################

#
# Set build type to CFE_APP. This allows us to 
# define different compiler flags for the cFE Core and Apps.
# 
BUILD_TYPE = CFE_APP

## 
## Include all necessary cFE make rules
## Any of these can be copied to a local file and 
## changed if needed.
##
##
##       cfe-config.mak contains PSP and OS selection
##
include ../cfe/cfe-config.mak
##
##       debug-opts.mak contains debug switches
##
include ../cfe/debug-opts.mak
##
##       compiler-opts.mak contains compiler definitions and switches/defines
##
include $(CFE_PSP_SRC)/$(PSP)/make/compiler-opts.mak

##
## Setup the include path for this subsystem
## The OS specific includes are in the build-rules.make file
##
## If this subsystem needs include files from another app, add the path here.
##
INCLUDE_PATH = \
-I$(OSAL_SRC)/inc \
-I$(CFE_CORE_SRC)/inc \
-I$(CFE_PSP_SRC)/inc \
-I$(CFE_PSP_SRC)/$(PSP)/inc \
-I$(CFS_APP_SRC)/inc \
-I$(CFS_APP_SRC)/$(APPTARGET)/fsw/src \
-I$(CFS_MISSION_INC) \
-I../cfe/inc \
-I../inc

##
## Define the VPATH make variable. 
## This can be modified to include source from another directory.
## If there is no corresponding app in the cfs-apps directory, then this can be discarded, or
## if the mission chooses to put the src in another directory such as "src", then that can be 
## added here as well.
##
VPATH = $(CFS_APP_SRC)/$(APPTARGET)/fsw/src 

##
## Include the common make rules for building a cFE Application
##
include $(CFE_CORE_SRC)/make/app-rules.mak
