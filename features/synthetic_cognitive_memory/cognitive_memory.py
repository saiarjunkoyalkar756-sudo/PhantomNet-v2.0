import datetime
import json
from backend_api.database import CognitiveMemoryDB

class CognitiveMemory:
    """
    Stores every attack, resolution, and learning as a vectorized episodic memory.
    Uses a SQLAlchemy session for persistence.
    """
    def __init__(self, db_session):
        self.db = db_session
        print("Initializing Synthetic Cognitive Memory with shared SQLAlchemy session...")

    def store_episode(self, threat_data: str, analysis_result: dict, resolution: str):
        """
        Stores or updates a threat episode in the database.
        """
        episode_data = {
            "timestamp": datetime.datetime.now().isoformat(),
            "threat_data": threat_data,
            "analysis": analysis_result,
            "resolution": resolution
        }
        episode_json = json.dumps(episode_data)
        
        # Check if the threat already exists
        existing_episode = self.db.query(CognitiveMemoryDB).filter(CognitiveMemoryDB.threat_data == threat_data).first()
        
        if existing_episode:
            existing_episode.episode_data = episode_json
            existing_episode.timestamp = datetime.datetime.now()
        else:
            new_episode = CognitiveMemoryDB(threat_data=threat_data, episode_data=episode_json)
            self.db.add(new_episode)
            
        self.db.commit()
        print(f"Stored/Updated episode for threat: {threat_data}")

    def recall_episode(self, threat_data: str):
        """
        Recalls a past episode from the database.
        """
        episode = self.db.query(CognitiveMemoryDB).filter(CognitiveMemoryDB.threat_data == threat_data).first()
        
        if episode:
            return json.loads(episode.episode_data)
        return None

    def get_all_episodes(self):
        """
        Returns all stored episodes from the database.
        """
        episodes = self.db.query(CognitiveMemoryDB).all()
        return [json.loads(episode.episode_data) for episode in episodes]