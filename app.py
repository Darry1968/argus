import configs
from flask import Flask
from models import db
from argus_app.routes import app_blueprint
from auth.routes import auth_blueprint
from flask_login import LoginManager

app = Flask(__name__)
login_manager = LoginManager()

# configuration
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///./test.db"
app.secret_key = "JaiMataDi"

login_manager.init_app(app)
db.init_app(app)
with app.app_context():
    db.create_all()

app.register_blueprint(app_blueprint)
app.register_blueprint(auth_blueprint)

if __name__ == '__main__':
    app.run(**configs.app_run['test'],debug=True)