drop table if exists users;
drop table if exists roles;
create table users(
username varchar(30) primary key,
password varchar(60)
)

;
create table roles(
id integer primary key AUTO_INCREMENT,
authority varchar(20),
username varchar(30) references users(username)
);
