count2=0
count4=0
count1XOR=0
count1=0
count1AND = [0]*0xA

#Run the loop from Stage2 to get the output and show that it is static
while (count1<0x1000ea):
    if (count1 & 3) - 1 == 0:
        for i in range(0xA):
            count1AND[i] = count1 & 0xFF
        count4 = count4 | 1
    elif (count1 & 3) - 2 ==0:
        count4 = count4 | 0x2
    count1+=1
print(count1, count4)
print(count1AND)
