import threading 

print(threading.active_count())

def looping():
    for i in range(100):
        print('1')

t1 = threading.Thread(target=looping)

t1.start()

t1.join()


for i in range(100):
    print('2')



