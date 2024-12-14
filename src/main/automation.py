import time
import subprocess

script_to_run = 'src/main/main.py' #path to the script you want to run for example: 'src/main/main.py'
when_to_stop = 100 #number of times to run the script
counter = 0 #dont touch

while True:
    try:
        # Run the script
        print(f'[{time.strftime("%d-%m-%Y %H:%M:%S", time.gmtime(time.time()))}]: Running...')
        subprocess.run(['sudo', 'python3', script_to_run], check=True) #for Windows: ['python', script_to_run]
    except subprocess.CalledProcessError as e:
        print(f'An error occurred while running the script: {e}')
        break
    except Exception as e:
        print(f'Unexpected error: {e}')
        break
    
    counter += 1
    if counter == when_to_stop: 
        print('Stopping the program...')
        break