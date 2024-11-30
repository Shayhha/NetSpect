import os

# save the absolute path to the models directory
MODELS_PATH = os.path.abspath(os.path.dirname(__file__))

def getModelPath(filename):
    '''
    Helper function for returning the path to a file inside the models folder.
    '''
    return os.path.join(MODELS_PATH, filename)