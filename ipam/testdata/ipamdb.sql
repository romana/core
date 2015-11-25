-- MySQL dump 10.13  Distrib 5.6.23-ndb-7.4.5, for osx10.8 (x86_64)
--
-- Host: pax.cru6yyfomzkp.us-west-1.rds.amazonaws.com    Database: pax
-- ------------------------------------------------------
-- Server version	5.6.23-log

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Current Database: `pax`
--

CREATE DATABASE /*!32312 IF NOT EXISTS*/ `pax` /*!40100 DEFAULT CHARACTER SET latin1 */;

USE `pax`;

--
-- Table structure for table `datacenters`
--

DROP TABLE IF EXISTS `datacenters`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `datacenters` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `prefix` int(11) unsigned DEFAULT '10',
  `prefix_bits` int(11) unsigned DEFAULT '8',
  `port_bits` int(11) DEFAULT '6',
  `tenant_bits` int(11) unsigned DEFAULT '6',
  `segment_bits` int(11) unsigned DEFAULT '6',
  `endpoint_space_bits` int(11) unsigned DEFAULT '0',
  `name` varchar(128) DEFAULT NULL,
  `ip_version` enum('IPv4','IPv6') DEFAULT 'IPv4',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `filters`
--

DROP TABLE IF EXISTS `filters`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `filters` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(128) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `hosts`
--

DROP TABLE IF EXISTS `hosts`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `hosts` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(128) DEFAULT NULL,
  `leaf` int(11) unsigned DEFAULT NULL,
  `sequence` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `leaf` (`leaf`,`sequence`),
  UNIQUE KEY `leaf_2` (`leaf`,`name`),
  CONSTRAINT `hosts_ibfk_1` FOREIGN KEY (`leaf`) REFERENCES `leafs` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `leaf_spine`
--

DROP TABLE IF EXISTS `leaf_spine`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `leaf_spine` (
  `leaf` int(11) unsigned DEFAULT NULL,
  `spine` int(11) unsigned DEFAULT NULL,
  KEY `leaf` (`leaf`),
  KEY `spine` (`spine`),
  CONSTRAINT `leaf_spine_ibfk_1` FOREIGN KEY (`leaf`) REFERENCES `leafs` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `leaf_spine_ibfk_2` FOREIGN KEY (`spine`) REFERENCES `spines` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `leaf_types`
--

DROP TABLE IF EXISTS `leaf_types`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `leaf_types` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(128) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `leafs`
--

DROP TABLE IF EXISTS `leafs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `leafs` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `datacenter` int(11) unsigned DEFAULT NULL,
  `sequence` int(11) NOT NULL,
  `leaf_type` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `datacenter` (`datacenter`,`sequence`),
  KEY `leaf_type` (`leaf_type`),
  CONSTRAINT `leafs_ibfk_1` FOREIGN KEY (`datacenter`) REFERENCES `datacenters` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `leafs_ibfk_2` FOREIGN KEY (`leaf_type`) REFERENCES `leaf_types` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `policies`
--

DROP TABLE IF EXISTS `policies`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `policies` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(128) NOT NULL,
  `src` int(11) unsigned NOT NULL,
  `dst` int(11) unsigned NOT NULL,
  `filter` int(11) unsigned NOT NULL,
  `scope` enum('Local','Global') DEFAULT 'Local',
  PRIMARY KEY (`id`),
  KEY `src` (`src`),
  KEY `dst` (`dst`),
  KEY `filter` (`filter`),
  CONSTRAINT `policies_ibfk_1` FOREIGN KEY (`src`) REFERENCES `segments` (`id`),
  CONSTRAINT `policies_ibfk_2` FOREIGN KEY (`src`) REFERENCES `segments` (`id`),
  CONSTRAINT `policies_ibfk_3` FOREIGN KEY (`dst`) REFERENCES `segments` (`id`),
  CONSTRAINT `policies_ibfk_4` FOREIGN KEY (`filter`) REFERENCES `filters` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `segments`
--

DROP TABLE IF EXISTS `segments`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `segments` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(128) DEFAULT NULL,
  `sequence` int(11) NOT NULL,
  `tenant` int(11) unsigned NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `tenant` (`tenant`,`sequence`),
  UNIQUE KEY `tenant_2` (`tenant`,`name`),
  CONSTRAINT `segments_ibfk_1` FOREIGN KEY (`tenant`) REFERENCES `tenants` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `spine_types`
--

DROP TABLE IF EXISTS `spine_types`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `spine_types` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(128) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `spines`
--

DROP TABLE IF EXISTS `spines`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `spines` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `datacenter` int(11) unsigned DEFAULT NULL,
  `spine_type` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `datacenter` (`datacenter`),
  KEY `spine_type` (`spine_type`),
  CONSTRAINT `spines_ibfk_1` FOREIGN KEY (`datacenter`) REFERENCES `datacenters` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `spines_ibfk_2` FOREIGN KEY (`spine_type`) REFERENCES `spine_types` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `tenants`
--

DROP TABLE IF EXISTS `tenants`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `tenants` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `datacenter` int(11) unsigned DEFAULT NULL,
  `name` varchar(128) NOT NULL,
  `external_id` varchar(128) DEFAULT NULL,
  `sequence` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `name` (`name`,`datacenter`),
  UNIQUE KEY `sequence` (`sequence`,`datacenter`),
  KEY `datacenter` (`datacenter`),
  CONSTRAINT `tenants_ibfk_1` FOREIGN KEY (`datacenter`) REFERENCES `datacenters` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `vms`
--

DROP TABLE IF EXISTS `vms`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `vms` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `host` int(11) unsigned DEFAULT NULL,
  `segment` int(11) unsigned DEFAULT NULL,
  `ip` varchar(128) DEFAULT NULL,
  `external_id` varchar(128) DEFAULT NULL,
  `name` varchar(128) DEFAULT NULL,
  `sequence` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `host` (`host`,`segment`,`sequence`),
  KEY `segment` (`segment`),
  CONSTRAINT `vms_ibfk_2` FOREIGN KEY (`segment`) REFERENCES `segments` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `vms_ibfk_3` FOREIGN KEY (`host`) REFERENCES `hosts` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2015-09-09 15:13:07
