import time
import subprocess
import gc

scriptToRun = 'src/main/main.py' #path to the script you want to run for example: 'src/main/main.py'
whenToStop = 400 #number of times to run the script
counter = 0 #dont touch

while True:
    try:
        print(f'[{time.strftime("%d-%m-%Y %H:%M:%S", time.gmtime())}]: Running...')
        # for Windows: ['python', scriptToRun]   for MacOS: ['sudo', 'python3', scriptToRun]
        process = subprocess.Popen(['python', scriptToRun], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        process.wait()
        process.kill()
    except Exception as e:
        print(f'Unexpected error: {e}')
        break

    # clean up resources
    gc.collect()
    print(f'[{time.strftime("%d-%m-%Y %H:%M:%S", time.gmtime())}]: Finished.\n')

    counter += 1
    if counter >= whenToStop:
        print('Stopping the program...')
        break