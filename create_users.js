let userDb = db.getSiblingDB("user");
let systemDate = new Date();
let users = [];
let userNo = 0;
let limit = 10;

if (!userDb.getCollectionNames().includes('users')) {
    userDb.createCollection('users');
    console.log('Created collection users successfully');
}

for (let i = 0; i < limit; i++) {
    userNo = i + 1;
    let user = {
        "username": "test" + userNo.toString().padStart(3, '0'),
        "password": "$2a$10$uRoMfOttIfejBIbc/zmSU.MPU5.OXvZ7PbQy.oitnV2atJdIave3m",
        "no": userNo.toString().padStart(3, '0'),
        "email": "test@test.com",
        "role": "admin"
    };
    users.push(user);
}
userDb.users.insertMany(users);

console.log("Create users finished !!");
