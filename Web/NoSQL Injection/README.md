# NoSQL Injection 
- [Introduction](#introduction)
    - [MongoDB](#mongodb)



## Introduction
- There are four main types of NoSQL databases, and unlike relational databases, which all store data similarly in tables, rows, and columns, the way NoSQL databases store data varies significantly across the different categories and implementations.

|Type|	Description|	Top 3 Engines (as of November 2022)|
|----|-------------|---------------------------------------|
|Document-Oriented Database|	Stores data in documents which contain pairs of fields and values. These documents are typically encoded in formats such as JSON or XML.|	MongoDB, Amazon DynamoDB, Google Firebase - Cloud Firestore|
|Key-Value Database|	A data structure that stores data in key:value pairs, also known as a dictionary.	Redis, Amazon DynamoDB, Azure Cosmos DB|
|Wide-Column Store|	Used for storing enormous amounts of data in tables, rows, and columns like a relational database, but with the ability to handle more ambiguous data types.|	Apache Cassandra, Apache HBase, Azure Cosmos DB|
|Graph Database	|Stores data in nodes and uses edges to define relationships.|	Neo4j, Azure Cosmos DB, Virtuoso|

### MongoDB
- MongoDB is a document-oriented database, which means data is stored in collections of documents composed of fields and values. 
- In MongoDB, these documents are encoded in BSON (Binary JSON). An example of a document that may be stored in a MongoDB database is:
```json
{
  _id: ObjectId("63651456d18bf6c01b8eeae9"),
  type: 'Granny Smith',
  price: 0.65
}
```
- Here we can see the document's fields (`type`, `price`) and their respective values ('Granny Smith', '0.65'). The field `_id` is reserved by MongoDB to act as a document's primary key, and it must be unique throughout the entire collection.

- We can use mongosh to interact with a MongoDB database from the command line by passing the connection string. Note that 27017/tcp is the default port for MongoDB.
```bash
abdeonix@htb[/htb]$ mongosh mongodb://127.0.0.1:27017

Current Mongosh Log ID: 636510136bfa115e590dae03
Connecting to:          mongodb://127.0.0.1:27017/?directConnection=true&serverSelectionTimeoutMS=2000&appName=mongosh+1.6.0
Using MongoDB:          6.0.2
Using Mongosh:          1.6.0

For mongosh info see: https://docs.mongodb.com/mongodb-shell/

test>
```
- We can check which databases exist like this:
```bash
test> show databases
admin       72.00 KiB
config     108.00 KiB
local       40.00 KiB
```
> [!NOTE]
> MongoDB does not create a database until you first store data in that database. 

- We can "switch" to a new database called academy by using the use command:
```bash
test> use academy
switched to db academy
academy>
```
- Similarly to creating a database, MongoDB only creates a collection when you first insert a document into that collection. We can insert data into a collection in several ways.

- We can insert a single document into the apples collection like this:

```bash
academy> db.apples.insertOne({type: "Granny Smith", price: 0.65})
{
  acknowledged: true,
  insertedId: ObjectId("63651456d18bf6c01b8eeae9")
}
```
- And we can insert multiple documents into the apples collection like this:
```bash
academy> db.apples.insertMany([{type: "Golden Delicious", price: 0.79}, {type: "Pink Lady", price: 0.90}])
{
  acknowledged: true,
  insertedIds: {
    '0': ObjectId("6365147cd18bf6c01b8eeaea"),
    '1': ObjectId("6365147cd18bf6c01b8eeaeb")
  }
}
```

- Let's say we wanted to check the price of Granny Smith apples. One way to do this is by specifying a document with fields and values we want to match:
```bash
academy> db.apples.find({type: "Granny Smith"})
{
  _id: ObjectId("63651456d18bf6c01b8eeae9"),
  type: 'Granny Smith',
  price: 0.65
}
```
- Or perhaps we wanted to list all documents in the collection. We can do this by passing an empty document (since it is a subset of all documents):
```bash
academy> db.apples.find({})
[
  {
    _id: ObjectId("63651456d18bf6c01b8eeae9"),
    type: 'Granny Smith',
    price: 0.65
  },
  {
    _id: ObjectId("6365147cd18bf6c01b8eeaea"),
    type: 'Golden Delicious',
    price: 0.79
  },
  {
    _id: ObjectId("6365147cd18bf6c01b8eeaeb"),
    type: 'Pink Lady',
    price: 0.90
  }
]
```
- If we wanted to do more advanced queries, such as finding all apples whose type starts with a 'G' and whose price is less than 0.70, we would have to use a combination of query operators. There are many query operators in MongoDB. There are many query operators in MongoDB, but some of the most common are:

|Type|	Operator|	Description|	Example|
|----|----------|--------------|-----------|
|Comparison|	`$eq`|	Matches values which are equal to a specified value|	`type: {$eq: "Pink Lady"}`|
|Comparison|	`$gt`|	Matches values which are greater than a specified value|	`price: {$gt: 0.30}`|
|Comparison|	`$gte`|	Matches values which are greater than or equal to a specified value	|`price: {$gte: 0.50}`|
|Comparison|	`$in`|	Matches values which exist in the specified array	|`type: {$in: ["Granny Smith", "Pink Lady"]}`|
|Comparison|	`$lt`|	Matches values which are less than a specified value	|`price: {$lt: 0.60}`|
|Comparison|	`$lte`|	Matches values which are less than or equal to a specified value	|`price: {$lte: 0.75}`|
|Comparison|	`$nin`|	Matches values which are not in the specified array	|`type: {$nin: ["Golden Delicious", "Granny Smith"]}`|
|Logical|	`$and`|	Matches documents which meet the conditions of both specified queries	|`$and: [{type: 'Granny Smith'}, {price: 0.65}]`|
|Logical|	`$not`|	Matches documents which do not meet the conditions of a specified query	|`type: {$not: {$eq: "Granny Smith"}}`|
|Logical|	`$nor`|	Matches documents which do not meet the conditions of any of the specified queries	|`$nor: [{type: 'Granny Smith'}, {price: 0.79}]`|
|Logical|	`$or`	|Matches documents which meet the conditions of one of the specified queries	|`$or: [{type: 'Granny Smith'}, {price: 0.79}]`|
|Evaluation|	`$mod`|	Matches values which divided by a specific divisor have the specified remainder	|`price: {$mod: [4, 0]}`|
|Evaluation|	`$regex`|	Matches values which match a specified RegEx	|`type: {$regex: /^G.*/}`|
|Evaluation|	`$where`|	Matches documents which satisfy a JavaScript expression	|`$where: 'this.type.length === 9'`|


- Going back to the example from before, if we wanted to select all apples whose type starts with a 'G' and whose price is less than 0.70, we could do this:
```bash
academy> db.apples.find({
    $and: [
        {
            type: {
                $regex: /^G/
            }
        },
        {
            price: {
                $lt: 0.70
            }
        }
    ]
});
[
  {
    _id: ObjectId("63651456d18bf6c01b8eeae9"),
    type: 'Granny Smith',
    price: 0.65
  }
]
```

- Alternatively, we could use the $where operator to get the same result:
```bash
academy> db.apples.find({$where: `this.type.startsWith('G') && this.price < 0.70`});
[
  {
    _id: ObjectId("63651456d18bf6c01b8eeae9"),
    type: 'Granny Smith',
    price: 0.65
  }
]
```
- If we want to sort data from find queries, we can do so by appending the sort function. For example, if we want to select the top two apples sorted by price in descending order we can do so like this:
```bash
academy> db.apples.find({}).sort({price: -1}).limit(2)
[
  {
    _id: ObjectId("6365147cd18bf6c01b8eeaeb"),
    type: 'Pink Lady',
    price: 0.9
  },
  {
    _id: ObjectId("6365147cd18bf6c01b8eeaea"),
    type: 'Golden Delicious',
    price: 0.79
  }
]
```
- If we wanted to reverse the sort order, we would use 1 (Ascending) instead of -1 (Descending). Note the .limit(2) at the end, which allows us to set a limit on the number of results to be returned.

- Update operations take a filter and an update operation. The filter selects the documents we will update, and the update operation is carried out on those documents. Similar to the query operators, there are update operators in MongoDB. The most commonly used update operator is $set, which updates the specified field's value.

- Imagine that the price for Granny Smith apples has risen from 0.65 to 1.99 due to inflation. To update the document, we would do this:
```bash
academy> db.apples.updateOne({type: "Granny Smith"}, {$set: {price: 1.99}})
{
  acknowledged: true,
  insertedId: null,
  matchedCount: 1,
  modifiedCount: 1,
  upsertedCount: 0
}
```

- If we want to increase the prices of all apples at the same time, we could use the $inc operator and do this:
```bash
academy> db.apples.updateMany({}, {$inc: {quantity: 1, "price": 1}})
{
  acknowledged: true,
  insertedId: null,
  matchedCount: 3,
  modifiedCount: 3,
  upsertedCount: 0
}
```

- The $set operator allows us to update specific fields in an existing document, but if we want to completely replace the document, we can do that with replaceOne like this:

```bash
academy> db.apples.replaceOne({type:'Pink Lady'}, {name: 'Pink Lady', price: 0.99, color: 'Pink'})
{
  acknowledged: true,
  insertedId: null,
  matchedCount: 1,
  modifiedCount: 1,
  upsertedCount: 0
}
```

- Removing a document is very similar to selecting documents. We pass a query, and the matching documents are removed. Let's say we wanted to remove apples whose prices are less than 0.80:

```bash
academy> db.apples.remove({price: {$lt: 0.8}})
{ acknowledged: true, deletedCount: 2 }
```