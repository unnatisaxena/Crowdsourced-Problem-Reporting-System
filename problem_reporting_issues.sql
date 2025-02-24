-- MySQL dump 10.13  Distrib 9.0.1, for Win64 (x86_64)
--
-- Host: localhost    Database: problem_reporting
-- ------------------------------------------------------
-- Server version	9.0.1

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `issues`
--

DROP TABLE IF EXISTS `issues`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `issues` (
  `issues_Id` int NOT NULL AUTO_INCREMENT,
  `Users_Id` int DEFAULT NULL,
  `Issue_Description` text,
  `Photo_url` varchar(225) DEFAULT NULL,
  `location` varchar(225) DEFAULT NULL,
  `Status` enum('reported','in-process','resolved') DEFAULT 'reported',
  `Reported_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`issues_Id`),
  KEY `users_id_idx` (`Users_Id`),
  CONSTRAINT `users_id` FOREIGN KEY (`Users_Id`) REFERENCES `users` (`Users_Id`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `issues`
--

LOCK TABLES `issues` WRITE;
/*!40000 ALTER TABLE `issues` DISABLE KEYS */;
INSERT INTO `issues` VALUES (1,2,'Broken streetlight near park','https://media.istockphoto.com/id/496026170/photo/broken-street-lamp.jpg?s=612x612&w=0&k=20&c=1bX4binyYkD8P_ZzHbfRTspKowTIGoTkSjxvbcjAkY4=','Central Park, NY','reported','2025-02-19 16:02:54'),(2,3,'Garbage overflow near school','https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcSsrbcQkGU1seiyksRiBTE1mXNoet2qeduLtw&s','5th Avenue, NY','in-process','2025-02-19 16:02:54'),(3,1,'Damaged sidewalk in front of mall','https://www.shutterstock.com/image-photo/pavement-surface-damaged-broken-brick-600nw-2176938397.jpg','Broadway, NY','resolved','2025-02-19 16:02:54');
/*!40000 ALTER TABLE `issues` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2025-02-19 21:49:27
