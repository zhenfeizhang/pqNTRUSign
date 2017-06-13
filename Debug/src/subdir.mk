################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../src/Gaussian-pqNTRUSign.c \
../src/example.c \
../src/param.c 

OBJS += \
./src/Gaussian-pqNTRUSign.o \
./src/example.o \
./src/param.o 

C_DEPS += \
./src/Gaussian-pqNTRUSign.d \
./src/example.d \
./src/param.d 


# Each subdirectory must supply rules for building sources it contributes
src/%.o: ../src/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	gcc -I/usr/local/include/ -I/usr/include/ -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


