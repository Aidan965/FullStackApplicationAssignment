from flask import Flask, request, jsonify, make_response
from pymongo import MongoClient
from bson import ObjectId
import string
import jwt
import datetime
from functools import wraps
import bcrypt
from flask_cors import CORS
from collections import Counter

app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = 'mysecret'

client = MongoClient("mongodb://127.0.0.1:27017")
db = client.project

laureates = db.laureates
prizes = db.prizes
countries = db.countries
blacklist = db.blacklist
staff = db.staff


#
#
#   Wrappers
#
#


def jwt_required(func):
    @wraps(func)
    def jwt_required_wrapper(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify(\
                {'message' : 'Token is missing'}), 401
        try:
            jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        except:
            return jsonify(\
                    {'message' : 'Token is invalid'}), 401
        bl_token = blacklist.find_one({"token":token})
        if bl_token is not None:
            return make_response(jsonify({"message":"Token has been cancelled"}), 401)
        return func(*args, **kwargs)
    
    return jwt_required_wrapper


def admin_required(func):
    @wraps(func)
    def admin_required_wrapper(*args, **kwargs):
        token = request.headers['x-access-token']
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        
        if data["admin"]:
            return func(*args, **kwargs)
        else:
            return make_response(jsonify({"message": "Admin access required"}), 401)
    return admin_required_wrapper




#
#
#   Nobel laureates endpoints
#
#


# Return all Nobel laureates
@app.route("/api/v1/laureates", methods=["GET"])
def show_all_laureates():
    page_num, page_size = 1, 10

    if request.args.get("pn"):
        page_num = int(request.args.get("pn"))
    if request.args.get("ps"):
        page_size = int(request.args.get("ps"))
    page_start = (page_size * (page_num - 1))

    data = []
    for laureate in laureates.find().skip(page_start).limit(page_size):
        laureate["_id"] = str(laureate["_id"])
        for prize in laureate["prizes"]:
            prize["_id"] = str(prize["_id"])
        data.append(laureate)
    return make_response(jsonify(data), 200)


# Return a specific Nobel laureate
@app.route("/api/v1/laureates/<string:id>", methods=["GET"])
def show_one_laureate(id):
    if all(char in string.hexdigits for char in id) and len(id) == 24:
        laureate = laureates.find_one( {"_id" : ObjectId(id)} )
        data = []

        if laureate is not None:
            laureate["_id"] = str(laureate["_id"])
            for prize in laureate["prizes"]:
                prize["_id"] = str(prize["_id"])
            data.append(laureate)
            return make_response(jsonify(data), 200)
        else:
            return make_response(jsonify( {"error" : "Invalid laureate ID"} ), 404)
    else:
        return make_response(jsonify( {"error" : "ID should be 24 characters long or contains illegal characters"} ), 400)


# Get the most decorated Universities
@app.route("/api/v1/laureates/universities/top20", methods=["GET"])
def get_most_decorated_universities():
    data = []
    university_frequency = {}

    for prize in laureates.find({}, {"prizes.affiliations.name" : 1, "_id" : 0}):
        if len(prize["prizes"][0]["affiliations"][0]) == 0:
            continue
        data.append(prize["prizes"][0]["affiliations"][0]["name"])

    university_frequency = Counter(data)  
    university_count = university_frequency.most_common()

    data_to_return = []
    counter = 0
    for university in university_count:
        data_to_return.append(university)
        counter += 1
        if counter == 20:
            break
    
    return make_response(jsonify(data_to_return), 200)


# Get the most decorated countries
@app.route("/api/v1/laureates/countries/top30", methods=["GET"])
def get_most_decorated_countries():
    data = []
    country_frequency = {}

    for country in laureates.find({}, { "bornCountryCode" : 1, "_id" : 0 }):
        try:                
            data.append(country["bornCountryCode"])
        except: 
            print("No country code found")

    country_frequency = Counter(data)  
    country_count = country_frequency.most_common()

    data_to_return = []
    counter = 0
    for country in country_count:
        data_to_return.append(country)
        counter += 1
        if counter == 30:
            break
    
    return make_response(jsonify(data_to_return), 200)

# Get the most decorated Nobel laureates/organisations
@app.route("/api/v1/laureates/highly_decorated", methods=["GET"])
def show_most_decorated_laureates():
    data = []

    for laureate in laureates.find( { "$where" : "this.prizes.length > 1" } ):
        laureate["_id"] = str(laureate["_id"])
        for prize in laureate["prizes"]:
            prize["_id"] = str(prize["_id"])
        data.append(laureate)
    
    if len(data) == 0:
        return make_response(jsonify( { "error" : "No laureates found" } ), 404)
    
    return make_response(jsonify(data), 200)


# Get Nobel laureates by country code
@app.route("/api/v1/laureates/countries/<string:country_code>", methods=["GET"])
def get_all_laureates_by_country(country_code):
    
    country_code = country_code.upper()

    page_num, page_size = 1, 20

    if request.args.get("pn"):
        page_num = int(request.args.get("pn"))
    if request.args.get("ps"):
        page_size = int(request.args.get("ps"))
    page_start = (page_size * (page_num - 1))

    if all(char in string.ascii_uppercase for char in country_code) and len(country_code) == 2:
        data = []

        for laureate in laureates.find( {"bornCountryCode" : country_code} ).skip(page_start).limit(page_size):
            laureate["_id"] = str(laureate["_id"])
            for prize in laureate["prizes"]:
                prize["_id"] = str(prize["_id"])
            data.append(laureate)

        if len(data) == 0:
            return make_response(jsonify( {"error" : "No Nobel Laureates exist for that country"} ), 404)

        return make_response(jsonify(data), 200)
    else:
        return make_response(jsonify( {"error" : "Country code should be only two letters long and contain only letters"} ), 400)


# Get Nobel laureates by affiliated University
@app.route("/api/v1/laureates/universities/<string:university>", methods=["GET"])
def get_all_laureates_affiliated_with_a_university(university):
    
    data = []

    for laureate in laureates.find({"prizes.affiliations.name" : university}):
        laureate["_id"] = str(laureate["_id"])
        for prize in laureate["prizes"]:
            prize["_id"] = str(prize["_id"])
        data.append(laureate)

    if len(data) == 0:
        return make_response(jsonify( {"error" : "No Nobel Laureates exist for that university or university not found"} ), 404)

    return make_response(jsonify(data), 200)


# Add a new Nobel laureate
@app.route("/api/v1/laureates", methods=["POST"])
#@jwt_required
#@admin_required
def add_laureate():
    if "firstname" in request.form and "surname" in request.form and "bornCountry" in request.form \
        and "born" in request.form and "died" in request.form and "bornCity" in request.form and "gender" in request.form:
        new_laureate = {
            "firstname": request.form["firstname"],
            "surname": request.form["surname"],
            "born": request.form["born"],
            "died": request.form["died"],
            "bornCountry": request.form["bornCountry"],
            "bornCity": request.form["bornCity"],
            "gender": request.form["gender"],
            "prizes": []
        }

        new_laureate_id = laureates.insert_one(new_laureate)
        new_laureate_link = "http://localhost:5000/api/v1/laureates/" + str(new_laureate_id.inserted_id)
        return make_response(jsonify( { "url" : new_laureate_link } ), 201)

    else:
        return make_response(jsonify( {"error" : "Missing required form data"} ), 404)


# Edit an existing Nobel laureate
@app.route("/api/v1/laureates/<string:id>", methods=["PUT"])
# @jwt_required
#@admin_required
def edit_laureate(id):
    if all(char in string.hexdigits for char in id) and len(id) == 24:
        if "firstname" in request.form and "surname" in request.form:

            result = laureates.update_one(
                {"_id" : ObjectId(id)},
                {
                    "$set" : {
                        "firstname" : request.form["firstname"],
                        "surname" : request.form["surname"]
                    }
                })
            
            if result.matched_count == 1:
                edited_laureate_link = "http://localhost:5000/api/v1/laureates/" + id
                return make_response(jsonify( {"url" : edited_laureate_link} ), 200)
            else:
                return make_response(jsonify( {"error" : "Invalid Laureate ID"} ), 404)
        else:
            return make_response(jsonify( {"error" : "Missing form data"} ), 400)
    else:
        return make_response(jsonify( {"error" : "ID is not 24 characters long or contains invalid characters"} ), 400)


# Delete a Nobel Laureate
@app.route("/api/v1/laureates/<string:id>", methods=["DELETE"])
# @jwt_required
# @admin_required
def delete_laureate(id):
    if all(char in string.hexdigits for char in id) and len(id) == 24:
        result = laureates.delete_one( {"_id" : ObjectId(id) } )
        if result.deleted_count == 1:
            return make_response(jsonify( {} ), 204)
        else:
            return make_response(jsonify( {"error" : "Invalid Laureate ID"} ), 404)
    else:
        return make_response(jsonify({ "error" : "ID is not 24 characters long or contains invalid characters"}), 400)


#
#
#   Nobel prize endpoints
#
#


# Get all Nobel prize winners
@app.route("/api/v1/prizes", methods=["GET"])
def show_all_nobel_prizes():
    page_num, page_size = 1, 10
    if request.args.get('pn'):
        page_num = int(request.args.get('pn'))
    if request.args.get('ps'):
        page_size = int(request.args.get('ps'))
    page_start = (page_size * (page_num - 1))

    data = []

    for prize in prizes.find().skip(page_start).limit(page_size):
        prize["_id"] = str(prize["_id"])
        data.append(prize)
    return make_response(jsonify(data), 200)


# Get Nobel prizes by category
@app.route("/api/v1/prizes/category/<string:category>", methods=["GET"])
def get_nobel_prizes_by_category(category):
    data = []

    page_num, page_size = 1, 10
    if request.args.get('pn'):
        page_num = int(request.args.get('pn'))
    if request.args.get('ps'):
        page_size = int(request.args.get('ps'))
    page_start = (page_size * (page_num - 1))

    for prize in prizes.find( { "category" : category}).skip(page_start).limit(page_size):
        prize["_id"] = str(prize["_id"])
        data.append(prize)
    
    if len(data) == 0:
        return make_response(jsonify( {"error" : "No Nobel prizes exist for that year"} ), 404)
    return make_response(jsonify(data), 200)


# Get Nobel prizes by year
@app.route("/api/v1/prizes/year/<string:year>", methods=["GET"])
def get_nobel_prizes_by_year(year):
    data = []

    for prize in prizes.find( { "year" : year } ):
        prize["_id"] = str(prize["_id"])
        data.append(prize)
    
    if len(data) == 0:
        return make_response(jsonify( {"error" : "No Nobel prizes exist for that year"} ), 404)
    return make_response(jsonify(data), 200)


# Get Nobel prizes by category and year
@app.route("/api/v1/prizes/<string:category>/<string:year>", methods=["GET"])
def get_nobel_prizes_by_category_and_by_year(category, year):
    data = []

    for prize in prizes.find( {"category" : category, "year" : year} ):
        prize["_id"] = str(prize["_id"])
        data.append(prize)

    if len(data) == 0:
        return make_response(jsonify( {"error" : "No Nobel prizes exist for that year"} ), 404)
    return make_response(jsonify(data), 200)


# Get individual Nobel prize
@app.route("/api/v1/prizes/<string:id>", methods=["GET"])
def show_nobel_prize(id):
    if all(char in string.hexdigits for char in id) and len(id) == 24:
        prize = prizes.find_one( {"_id" : ObjectId(id)} )
        data = []

        if prize is not None:
            prize["_id"] = str(prize["_id"])
            data.append(prize)
            return make_response(jsonify(data), 200)
        else:
            return make_response(jsonify( {"error" : "Invalid Nobel prize ID"} ), 404)
    else:
        return make_response(jsonify( {"error" : "ID should be 24 characters long or contains illegal characters"} ), 400)


# Add Nobel prize to Laureate
@app.route("/api/v1/prizes/<string:id>", methods=["POST"])
#@jwt_required
#@admin_required
def add_nobel_prize_to_laureate(id):
    if "year" in request.form and "category" in request.form and "motivation" in request.form and "share" in request.form \
        and "name" in request.form and "city" in request.form and "country" in request.form:
        new_nobel_prize = {
            "_id" : ObjectId(),
            "year" : request.form["year"],
            "category" : request.form["category"],
            "motivation" : request.form["motivation"],
            "share" : request.form["share"],
            "affiliations" : [
                {
                    "name" : request.form["name"],
                    "city" : request.form["city"],
                    "country" : request.form["country"]
                }
            ]
        }

        # Prizes collection requires different data structure
        new_nobel_prize_collection = {
            "_id" : new_nobel_prize["_id"],
            "year" : request.form["year"],
            "category" : request.form["category"],       
            "laureates" : [
                {
                    "firstname" : request.form["firstname"],
                    "surname" : request.form["surname"],
                    "motivation" : request.form["motivation"],
                    "share" : request.form["share"],
                    "profileImage" : request.form["image"]
                }
            ]
        }
    else:
        return make_response(jsonify( {"error" : "Missing form data"} ), 404)

    if all(char in string.hexdigits for char in id) and len(id) == 24:
        result = laureates.find_one( {"_id" : ObjectId(id)} )
        if result is not None:
            laureates.update_one( 
                {"_id" : ObjectId(id)},
                {"$push" : {"prizes" : new_nobel_prize}} 
            )
            # TODO if prize already contains laureate call new method to add laureate to prize
            prizes.insert_one(new_nobel_prize_collection)

            new_nobel_prize_link = "http://localhost:5000/api/v1/prizes/" + str(new_nobel_prize["_id"])
            return make_response(jsonify( {"url" : new_nobel_prize_link} ), 201)
        else:
            return make_response(jsonify( {"error" : "Invalid laureate ID"} ), 404)
    else:
        return make_response(jsonify( {"error" : "ID should be 24 characters long or contains illegal characters"} ), 400)


# Edit Nobel prize
@app.route("/api/v1/prizes/<string:id>", methods=["PUT"])
# @jwt_required
# @admin_required
def update_nobel_prize(id):
    if "motivation" in request.form:
        edited_prize = {
            "laureates": [
                {
                    "motivation" : request.form["motivation"]
                }
            ]
        }
    else:
        return make_response(jsonify( {"error" : "Missing form data"} ), 404)
  
    if all(char in string.hexdigits for char in id) and len(id) == 24:
        prize = prizes.find_one( { "_id" : ObjectId(id) } )

        if prize is None:
            return make_response(jsonify( {"error" : "bad prize ID"} ), 404)
        
        prizes.update_one( {"_id" : ObjectId(id) }, {"$set" : edited_prize})
        edited_prize_url = "http://localhost:5000/api/v1/prizes/" + id
        
        return make_response(jsonify( {"url" : edited_prize_url} ), 200)
    
    else:
        return make_response(jsonify( {"error" : "ID should be 24 characters long or contains illegal characters"} ), 400)


# Delete Nobel prize
@app.route("/api/v1/prizes/<string:id>", methods=["DELETE"])
# @jwt_required
# @admin_required
def delete_nobel_prize(id):
    if all(char in string.hexdigits for char in id) and len(id) == 24:
        prize = prizes.find_one( { "_id" : ObjectId(id) } )

        if prize is None and prize is None:
            return make_response(jsonify({"error" : "bad Nobel prize ID"}), 404)

        prizes.delete_one( { "_id" : ObjectId(id) } )
        return make_response(jsonify({}), 204)
    else:
        return make_response(jsonify({ "error" : "ID is not 24 characters long or contains invalid characters"}), 400)


#
#
# Authentication endpoints
#
#

@app.route("/api/v1/login", methods=["GET"])
def login():
    auth = request.authorization
    if auth:
        user = staff.find_one({'username': auth.username})
        if user is not None:
            if bcrypt.checkpw(bytes(auth.password, 'UTF-8'), user["password"]):
                token = jwt.encode( \
                    {'user': auth.username,
                     'admin': user["admin"],
                     'exp': datetime.datetime.utcnow() + \
                            datetime.timedelta(minutes=30)
                    }, app.config['SECRET_KEY'])
                return make_response(jsonify({'token':token}), 200)
            else:
                return make_response(jsonify({'message':'Bad password'}), 401)
        else:
            return make_response(jsonify({'message': 'Bad username'}), 401)
    return make_response(jsonify({'message':'Authentication required'}), 401)


@app.route("/api/v1/logout", methods=["GET"])
@jwt_required
def logout():
    token = request.headers["x-access-token"]
    blacklist.insert_one({"token":token})
    return make_response(jsonify({"message":"Logout successful"}), 200)


if __name__ == "__main__":
    app.run(debug=True)