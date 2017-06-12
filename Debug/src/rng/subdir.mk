################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../src/rng/crypto_hash_sha512.c \
../src/rng/crypto_stream.c \
../src/rng/fastrandombytes.c \
../src/rng/randombytes.c \
../src/rng/shred.c 

OBJS += \
./src/rng/crypto_hash_sha512.o \
./src/rng/crypto_stream.o \
./src/rng/fastrandombytes.o \
./src/rng/randombytes.o \
./src/rng/shred.o 

C_DEPS += \
./src/rng/crypto_hash_sha512.d \
./src/rng/crypto_stream.d \
./src/rng/fastrandombytes.d \
./src/rng/randombytes.d \
./src/rng/shred.d 


# Each subdirectory must supply rules for building sources it contributes
src/rng/%.o: ../src/rng/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	gcc -I/usr/local/include/ -I/usr/include/ -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


