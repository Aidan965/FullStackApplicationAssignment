from bson.objectid import ObjectId
from pymongo import MongoClient

client = MongoClient("mongodb://127.0.0.1:27017")
db = client.project
laureates = db.laureates
prizes = db.prizes


def add_tributes_to_laureates():
    for laureate in laureates.find():
        tributes_of_laureates = []

        laureates.update_one( 
            { "_id" : laureate["_id"]},
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
            if len(laureate["prizes"]) > 2:
                laureates.update_one(
                { "_id" : laureate["_id"]}, 
                { "$set" : { "prizes.2._id" : ObjectId() } }
            )


def add_media_tag_to_laureate():
    for laureate in laureates.find():
        id = laureate["id"]
        laureates.update_one(
            { "_id" : laureate["_id"]},
            { "$set" : { "profileImage" : "assets/images/" + id + ".jpg" } }
        )


def add_media_tag_to_prize():
    for prize in prizes.find():
        try:
            for laureate in prize["laureates"]:
                id = laureate["id"]
                prizes.update_one(
                    { "laureates.id" : id },
                    { "$set" : { "laureates.$.profileImage" : "assets/images/" + id + ".jpg" } }
                )
        except:
            # No prize exists for this year, skipping iteration.
            continue


def add_text_index_to_laureate_name():
    laureates.create_index({"firstname" : "text", "surname" : "text"})

# add_tributes_to_laureates()
# add_object_id_to_prizes_in_laureates_collection()
# add_media_tag_to_laureate()
# add_media_tag_to_prize()
# add_text_index_to_laureate_name()