from bson.objectid import ObjectId
from pymongo import MongoClient

client = MongoClient("mongodb://127.0.0.1:27017")
db = client.project
laureates = db.laureates

def add_tributes_to_laureates():
    for laureate in laureates.find():
        tributes_of_laureates = []

        laureates.update_one( 
            { "id" : laureate["id"]},
            { "$set" : { "tributes" : tributes_of_laureates } }  
        )

def add_object_id_to_prizes_in_laureates_collection():
    for laureate in laureates.find():
        for prize in laureate["prizes"]:
            laureates.update_one(
                { "_id" : laureate["_id"]}, 
                { "$set" : { "prizes.0._id" : ObjectId() } }
            )
            if len(laureate["prizes"]) > 1:
                laureates.update_one(
                { "_id" : laureate["_id"]}, 
                { "$set" : { "prizes.1._id" : ObjectId() } }
            )


# add_tributes_to_laureates()
# add_object_id_to_prizes_in_laureates_collection()