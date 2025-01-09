import time
import subprocess
import gc

mainScriptToRun = 'src/main/main.py' #path to the script you want to run for example: 'src/main/main.py'
dnsScriptToRun = 'src/main/generateDNS.py' #path to the script that generates dns traffic
whenToStop = 5 #number of times to run the script
counter = 0 #dont touch

while True:
    try:
        print(f'[{time.strftime("%d-%m-%Y %H:%M:%S", time.localtime())}]: Running...')
        # for Windows: ['python', scriptToRun]   for MacOS: ['sudo', 'python3', scriptToRun]
        process1 = subprocess.Popen(['python', mainScriptToRun], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        process2 = subprocess.Popen(['python', dnsScriptToRun], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        process1.wait(timeout=60) #wait for up to 60 seconds
        process2.wait(timeout=60) 
    except subprocess.TimeoutExpired:
        print(f"Process exceeded timeout and will be killed.")
        process1.kill() #kill the process if it times out
        process2.kill() #kill the process if it times out
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        # ensure the process is terminated to avoid zombies
        if process1.poll() is None: #check if process is still running
            process1.kill()
        if process2.poll() is None: #check if process is still running
            process2.kill()

    # clean up resources
    gc.collect()
    print(f'[{time.strftime("%d-%m-%Y %H:%M:%S", time.localtime())}]: Finished. Iteration Number: {counter}\n')

    counter += 1
    if counter >= whenToStop:
        print('Stopping the program...')
        break