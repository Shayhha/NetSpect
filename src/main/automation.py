import time
import subprocess
import gc

scriptToRun = 'src/main/main.py' #path to the script you want to run for example: 'src/main/main.py'
whenToStop = 400 #number of times to run the script
counter = 0 #dont touch

while True:
    try:
        print(f'[{time.strftime("%d-%m-%Y %H:%M:%S", time.localtime())}]: Running...')
        # for Windows: ['python', scriptToRun]   for MacOS: ['sudo', 'python3', scriptToRun]
        process = subprocess.Popen(['sudo', 'python3', scriptToRun], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        process.wait(timeout=60)  # Wait for up to 60 seconds
    except subprocess.TimeoutExpired:
        print(f"Process exceeded timeout and will be killed.")
        process.kill()  # Kill the process if it times out
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        # Ensure the process is terminated to avoid zombies
        if process.poll() is None:  # Check if process is still running
            process.kill()

    # clean up resources
    gc.collect()
    print(f'[{time.strftime("%d-%m-%Y %H:%M:%S", time.gmtime())}]: Finished.\n')

    counter += 1
    if counter >= whenToStop:
        print('Stopping the program...')
        break