import configs
from flask import Flask
from models import db
from argus_app.routes import app_blueprint
from auth.routes import auth_blueprint, login_manager

app = Flask(__name__)

# configuration
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config["OWASP_API_KEY"] = "glcpt71nmqds2vgm4u510krid0"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///./test.db"
app.secret_key = "JaiMataDi"

login_manager.init_app(app)
db.init_app(app)

# Ensure the login view is set for unauthorized users
login_manager.login_view = 'auth.login'

with app.app_context():
    db.create_all()

app.register_blueprint(app_blueprint)
app.register_blueprint(auth_blueprint)

if __name__ == '__main__':
    app.run(**configs.app_run['test'],debug=True)