from flask import Flask, request
import time
import random
import logging

# simple Flask web server class, creates a web server at the given port for performing DoS HTTP GET Flood attacks
class FlaskServer:
    port = None #represents the port where the web server will run

    # constructor of Flask web server
    def __init__(self, port=8080):
        self.app = Flask(__name__)
        self.port = port
        self._configure_routes()
        logging.basicConfig(level=logging.INFO)

    # define the routes of our web server
    def _configure_routes(self): 
        @self.app.route('/') #default landing page
        def home():
            return "<html><body><h1>GET Request Successful</h1></body></html>"
        
        @self.app.route('/page1', methods=['GET', 'POST']) #route for Page 1
        def page1():
            self.simulate_delay()
            if request.method == 'POST':
                name = request.form.get('name', 'Anonymous')
                logging.info(f"Received form submission: name={name}")
                return f"<html><body><h1>Form Submitted Successfully</h1><p>Name: {name}</p></body></html>"
            return self.PAGE1_HTML

        @self.app.route('/page2', methods=['GET']) #route for Page 2
        def page2(): 
            self.simulate_delay()
            return self.PAGE2_HTML

    # simple method for sleeping for a random duration to simulate background tasks when switcing between pages
    @staticmethod
    def simulate_delay(minTime=0.5, maxTime=1.5):
        time.sleep(random.uniform(minTime, maxTime))

    # defining simple html and css for Page 1 of the web server
    @property
    def PAGE1_HTML(self):
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body { font-family: Arial, sans-serif; text-align: center; margin: 50px; }
                h1 { font-size: 2.5em; color: #333; }
                h2 { font-size: 1.8em; color: #555; }
                button { font-size: 1.2em; padding: 10px 20px; margin: 10px; background-color: #007BFF; color: white; border: none; border-radius: 5px; cursor: pointer; }
                button:hover { background-color: #0056b3; }
                input[type="text"] { font-size: 1em; padding: 5px; margin: 10px; width: 300px; border: 1px solid #ccc; border-radius: 5px; }
                input[type="submit"] { font-size: 1em; padding: 10px 20px; background-color: #28a745; color: white; border: none; border-radius: 5px; cursor: pointer; }
                input[type="submit"]:hover { background-color: #218838; }
            </style>
        </head>
        <body>
            <h1>Page 1</h1>
            <button onclick="window.location.href='/page2'">Go to Page 2</button>
            <h2>Submit Form</h2>
            <form action='/page1' method='POST'>
                <label for="name">Enter Name:</label>
                <input type="text" id="name" name="name" required>
                <input type="submit" value="Submit">
            </form>
        </body>
        </html>
        """

    # defining simple html and css for Page 2 of the web server
    @property
    def PAGE2_HTML(self):
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body { font-family: Arial, sans-serif; text-align: center; margin: 50px; }
                h1 { font-size: 2.5em; color: #333; }
                button { font-size: 1.2em; padding: 10px 20px; margin: 10px; background-color: #007BFF; color: white; border: none; border-radius: 5px; cursor: pointer; }
                button:hover { background-color: #0056b3; }
            </style>
        </head>
        <body>
            <h1>Page 2</h1>
            <button onclick="window.location.href='/page1'">Go to Page 1</button>
        </body>
        </html>
        """

    # simple run function for starting the web server on local host at the given port number
    def run(self):
        try:
            logging.info(f"Server started at port {self.port}")
            self.app.run(host="0.0.0.0", port=self.port)
        except KeyboardInterrupt:
            logging.info("Server is shutting down...")


# main function for starting the Flask server
if __name__ == "__main__":
    server = FlaskServer(port=8090)
    server.run() #run the Flask HTTP web server