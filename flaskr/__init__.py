import os
from flask import Flask


def create_app(test_config=None):
    # Fundamental Initialisation
    app = Flask(__name__, instance_relative_config=True)

    # Configuring automatically
    app.config.from_mapping(
        SECRET_KEY='dev',
        DATABASE=os.path.join(app.instance_path, 'flaskr.sqlite'),
    )

    # Rewriting if the "config.py" file is available
    if test_config is None:
        app.config.from_pyfile('config.py', silent=True)
    else:
        app.config.from_mapping(test_config)

    # Checking the instance path if it exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    @app.route("/hello")
    def index():
        return "Hello"

    return app
