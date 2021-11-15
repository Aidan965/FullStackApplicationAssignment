from pymongo import MongoClient
import bcrypt

client = MongoClient("mongodb://127.0.0.1:27017")
db = client.project      # select the database
staff = db.staff         # select the collection name

staff_list = [
          { 
            "name" : "Aidan Hughes",
            "username" : "aidan",  
            "password" : b"flask",
            "email" : "aidan@ulster.net",
            "admin" : True
          }
       ]

for new_admin_user in staff_list:
      new_admin_user["password"] = bcrypt.hashpw(new_admin_user["password"], bcrypt.gensalt())
      staff.insert_one(new_admin_user)
