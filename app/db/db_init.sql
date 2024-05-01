CREATE DATABASE test; 
use test; 

CREATE TABLE abc( 
    LetterID varchar(100) NOT NULL PRIMARY KEY,
    NumberID int NOT NULL,
);

INSERT INTO abc(LetterID, NumberID) 
VALUES ("a",1), ("b",2), ("c",3);
