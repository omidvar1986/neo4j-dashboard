# dashboard/neo4j_driver.py
import os
import logging
from neo4j import GraphDatabase

logger = logging.getLogger('neo4j_driver')

# Singleton instance of the driver
_driver = None

class Neo4jDriver:
    def __init__(self, uri, user, password):
        try:
            self.driver = GraphDatabase.driver(uri, auth=(user, password))
            # Verify connectivity
            self.driver.verify_connectivity()
            logger.info("Successfully connected to Neo4j at %s", uri)
        except Exception as e:
            logger.error("Failed to connect to Neo4j: %s", str(e))
            self.driver = None
            raise

    def close(self):
        if self.driver:
            self.driver.close()
            self.driver = None
            logger.info("Neo4j driver closed")

    def run_query(self, query, **parameters):
        if not self.driver:
            raise Exception("Neo4j driver is not initialized")
        try:
            with self.driver.session() as session:
                result = session.run(query, **parameters)
                return [record for record in result]
        except Exception as e:
            logger.error("Error running query: %s - %s", query, str(e))
            raise

def get_neo4j_driver():
    global _driver
    if _driver is None:
        uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
        user = os.getenv("NEO4J_USER", "neo4j")
        password = os.getenv("NEO4J_PASSWORD", "Milad1986")  # Replace with your actual Neo4j password
        try:
            _driver = Neo4jDriver(uri, user, password)
        except Exception as e:
            logger.error("Failed to initialize Neo4j driver: %s", str(e))
            _driver = None
    return _driver

def close_neo4j_driver():
    global _driver
    if _driver is not None:
        _driver.close()
        _driver = None