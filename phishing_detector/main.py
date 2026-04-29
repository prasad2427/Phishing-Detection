import os
from flask import Flask
from app.routes import main_bp

def create_app():
    # Specify template_folder relative to this file
    base_dir = os.path.dirname(os.path.abspath(__file__))
    template_dir = os.path.join(base_dir, 'templates')
    app = Flask(__name__, template_folder=template_dir)
    
    app.register_blueprint(main_bp)
    
    return app

if __name__ == '__main__':
    app = create_app()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
