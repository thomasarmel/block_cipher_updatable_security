from random import randint

DIGIT_COUNT = 30
DIVISOR_TEST = 8192

def is_prime(num, test_count):
    if num == 1:
        return False
    if test_count >= num:
        test_count = num - 1
    for x in range(test_count):
        val = randint(1, num - 1)
        if pow(val, num-1, num) != 1:
            return False
    return True

def generate_big_prime(n):
    found_prime = False
    while not found_prime:
        p = randint(2**(n-1), 2**n)
        if is_prime(p, 1000):
            return p

prime = generate_big_prime(DIGIT_COUNT)
while (prime - 1) % DIVISOR_TEST != 0:
    prime = generate_big_prime(DIGIT_COUNT)

print(prime)