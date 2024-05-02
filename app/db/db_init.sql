CREATE TABLE abc( 
    LetterID varchar(100) NOT NULL PRIMARY KEY,
    NumberID int
);

INSERT INTO abc(LetterID, NumberID) 
VALUES ("a",1), ("b",2), ("c",3);

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    password VARCHAR(255) NOT NULL
);

