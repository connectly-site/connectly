import os
from app import app, db

# Create the uploads folder
if not os.path.exists('static/uploads'):
    os.makedirs('static/uploads')
    print("Created uploads folder")

# Initialize the database
with app.app_context():
    db.create_all()
    print("Created database")

print("Setup complete!") 