# Simple Number Analyzer

num = int(input("Enter a number: "))

if num > 0:
    print("Positive number")
elif num < 0:
    print("Negative number")
else:
    print("Zero")

if num % 2 == 0:
    print("Even number")
else:
    print("Odd number")

print("Square:", num ** 2)
print("Cube:", num ** 3)