"""
Database utilities for the message processor.
"""
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from config.settings import DATABASE_URL, logger

class Database:
    """Database connection manager"""
    
    def __init__(self, db_url=None):
        """Initialize database connection"""
        self.db_url = db_url or DATABASE_URL
        self.engine = create_engine(self.db_url)
        self.Session = sessionmaker(bind=self.engine)
        logger.info(f"Database connection initialized with URL: {self.db_url}")
    
    def get_session(self):
        """Get a new database session"""
        return self.Session()
    
    def execute_query(self, query, params=None, commit=False):
        """Execute a query and return results"""
        session = self.get_session()
        try:
            if isinstance(query, str):
                query = text(query)
            
            result = session.execute(query, params or {})
            
            if commit:
                session.commit()
            
            return result
        except Exception as e:
            if commit:
                session.rollback()
            logger.error(f"Database error: {str(e)}")
            raise
        finally:
            session.close()

# Create a default database instance
db = Database() 