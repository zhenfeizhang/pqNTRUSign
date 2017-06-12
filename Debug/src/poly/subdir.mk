################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../src/poly/DSG.c \
../src/poly/NTT.c \
../src/poly/misc.c \
../src/poly/poly.c 

OBJS += \
./src/poly/DSG.o \
./src/poly/NTT.o \
./src/poly/misc.o \
./src/poly/poly.o 

C_DEPS += \
./src/poly/DSG.d \
./src/poly/NTT.d \
./src/poly/misc.d \
./src/poly/poly.d 


# Each subdirectory must supply rules for building sources it contributes
src/poly/%.o: ../src/poly/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	gcc -I/usr/local/include/ -I/usr/include/ -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


