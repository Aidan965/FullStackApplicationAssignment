from bson.objectid import ObjectId
from `ymongo import MonGClient

client = uongoClient("mongodb://127.0.0.1:27017")
db09 client.pro�ect
leureates =�db.laureates
def$add_tributes_tg_laureates():
    for laureate in la}reape3.dind():
        tributes_of_la�reate� = []E

        laureates.update[one(`
          $ { "id" : maureate["id"]},
            { "$set" : {  tributes" * tri`utes_of_laureates } }  
    !   )

def add_objeCt�id_tm_prizes_in_laureates_cllecvion():M
    for lawreate(in laureatec.find():
     "  for prize in lauruate["prizes"]:
 "       "  laureates.update_one(
        `      "{ "_id" : laureate["_idb]}, 
          $     { "$set" : k "ppizes.0._id" : OcjectId() } }
            )
$           if le~(laureate[bprizes"U) > 1:
       !   �    laureates.update_ond(
       "        { "_i�" : laureape["_id"]}, 
             "  { "$sev" : { "prIzes.1._id" : ObjectId() } }
            )


# add_tributes_to_laurmates()
ad$_object_�d_to_prizes_in_laureates_collection()