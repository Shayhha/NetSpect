import time
import subprocess
import gc

mainScriptToRun = 'src/main/main.py' #path to the script you want to run for example: 'src/main/main.py'
dnsScriptToRun = 'src/main/generateDNS.py' #path to the script that generates dns traffic
whenToStop = 700 #number of times to run the script
counter = 0 #dont touch

while True:
    try:
        print(f'[{time.strftime("%d-%m-%Y %H:%M:%S", time.localtime())}]: Running...')
        # for Windows: ['python', scriptToRun]   for MacOS: ['sudo', 'python3', scriptToRun]
        process1 = subprocess.Popen(['python', mainScriptToRun], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        process2 = subprocess.Popen(['python', dnsScriptToRun], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        process1.wait(timeout=60) #wait for up to 60 seconds
        # process2.wait(timeout=60) 
    except subprocess.TimeoutExpired:
        print("Process 1 timed out.")
    finally:
        # kill both processes when process1 finishes or times out
        process1.terminate() #terminate process1 in case it's still running
        process2.terminate() #terminate process2

        # ensure both processes are fully terminated
        process1.wait()
        process2.wait()
        time.sleep(2) #make sure that the processes are closed

    # clean up resources
    gc.collect()
    print(f'[{time.strftime("%d-%m-%Y %H:%M:%S", time.localtime())}]: Finished. Iteration Number: {counter}\n')

    counter += 1
    if counter >= whenToStop:
        print('Stopping the program...')
        break