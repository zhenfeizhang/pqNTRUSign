################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../src/KAT.c \
../src/packing.c \
../src/param.c \
../src/pqNTRUSign.c \
../src/sign.c \
../src/test.c 

OBJS += \
./src/KAT.o \
./src/packing.o \
./src/param.o \
./src/pqNTRUSign.o \
./src/sign.o \
./src/test.o 

C_DEPS += \
./src/KAT.d \
./src/packing.d \
./src/param.d \
./src/pqNTRUSign.d \
./src/sign.d \
./src/test.d 


# Each subdirectory must supply rules for building sources it contributes
src/%.o: ../src/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	gcc -I/usr/local/include/ -I/usr/include/ -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


