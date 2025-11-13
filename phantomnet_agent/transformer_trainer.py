import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import os
import re

# Configuration
LOG_FILE = os.path.join(os.path.dirname(__file__), "..", "logs", "attacks.log")
VOCABULARY = {
    "<PAD>": 0, "<UNK>": 1, "<SOS>": 2, "<EOS>": 3,
    "SCAN": 4, "SSH_ATTEMPT": 5, "CMD": 6, "FILE_UPLOAD": 7,
    "IP": 8, "PORT": 9, "DATA": 10, "LOGIN_ATTEMPT": 11,
    # Add more specific tokens based on expected log patterns
}

# Reverse vocabulary for decoding
REV_VOCABULARY = {v: k for k, v in VOCABULARY.items()}

class LogDataset(Dataset):
    def __init__(self, log_file, vocabulary, seq_len=128):
        self.vocabulary = vocabulary
        self.seq_len = seq_len
        self.sequences = self._load_and_tokenize_logs(log_file)

    def _load_and_tokenize_logs(self, log_file):
        sequences = []
        if not os.path.exists(log_file):
            print(f"Log file not found: {log_file}")
            return sequences

        with open(log_file, 'r') as f:
            for line in f:
                tokens = self._tokenize_line(line.strip())
                if tokens:
                    # Add Start Of Sequence and End Of Sequence tokens
                    indexed_tokens = [self.vocabulary.get("<SOS>")] + \
                                     [self.vocabulary.get(token, self.vocabulary["<UNK>"]) for token in tokens] + \
                                     [self.vocabulary.get("<EOS>")]
                    sequences.append(torch.tensor(indexed_tokens, dtype=torch.long))
        return sequences

    def _tokenize_line(self, line):
        # Simplified tokenization: split by spaces, and extract keywords
        tokens = []
        # Example: "SCAN from IP:192.168.1.1 PORT:22"
        # This is a very basic tokenizer. A more robust one would use regex or NLP techniques.
        
        # Extract known event types
        if "SCAN" in line:
            tokens.append("SCAN")
        if "SSH_ATTEMPT" in line:
            tokens.append("SSH_ATTEMPT")
        if "CMD:" in line:
            cmd_match = re.search(r"CMD:(\S+)", line)
            if cmd_match:
                tokens.append("CMD") # Or cmd_match.group(1) for specific command
        if "FILE_UPLOAD" in line:
            tokens.append("FILE")
        if "LOGIN_ATTEMPT" in line:
            tokens.append("LOGIN_ATTEMPT")

        # Extract IP, PORT, DATA
        if "IP:" in line:
            tokens.append("IP")
        if "PORT:" in line:
            tokens.append("PORT")
        if "Data:" in line:
            tokens.append("DATA")

        return tokens

    def __len__(self):
        return len(self.sequences)

    def __getitem__(self, idx):
        sequence = self.sequences[idx]
        # Pad or truncate sequence to seq_len
        if len(sequence) < self.seq_len:
            padding = torch.full((self.seq_len - len(sequence),), self.vocabulary["<PAD>"], dtype=torch.long)
            sequence = torch.cat((sequence, padding))
        elif len(sequence) > self.seq_len:
            sequence = sequence[:self.seq_len]
        return sequence

# Simple Transformer Model (Encoder only for next token prediction)
class TransformerModel(nn.Module):
    def __init__(self, vocab_size, d_model, nhead, num_encoder_layers, dim_feedforward, dropout, max_seq_len):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, d_model)
        self.positional_encoding = nn.Parameter(torch.zeros(1, max_seq_len, d_model))
        encoder_layer = nn.TransformerEncoderLayer(d_model, nhead, dim_feedforward, dropout, batch_first=True)
        self.transformer_encoder = nn.TransformerEncoder(encoder_layer, num_encoder_layers)
        self.fc_out = nn.Linear(d_model, vocab_size)
        self.dropout = nn.Dropout(dropout)

    def forward(self, src, src_mask=None):
        src = self.embedding(src) * torch.sqrt(torch.tensor(self.embedding.embedding_dim, dtype=torch.float32))
        src = src + self.positional_encoding[:, :src.size(1), :]
        src = self.dropout(src)
        output = self.transformer_encoder(src, src_mask)
        output = self.fc_out(output)
        return output

# Configuration
MODEL_PATH = os.path.join(os.path.dirname(__file__), "transformer_model.pth")

def train_transformer_model():
    # Hyperparameters
    VOCAB_SIZE = len(VOCABULARY)
    D_MODEL = 64 # Embedding dimension
    NHEAD = 4 # Number of attention heads
    NUM_ENCODER_LAYERS = 2
    DIM_FEEDFORWARD = 128
    DROPOUT = 0.1
    MAX_SEQ_LEN = 128
    BATCH_SIZE = 32
    NUM_EPOCHS = 10
    LEARNING_RATE = 0.001

    # Load data
    dataset = LogDataset(LOG_FILE, VOCABULARY, MAX_SEQ_LEN)
    dataloader = DataLoader(dataset, batch_size=BATCH_SIZE, shuffle=True)

    # Initialize model, optimizer, loss function
    model = TransformerModel(VOCAB_SIZE, D_MODEL, NHEAD, NUM_ENCODER_LAYERS, DIM_FEEDFORWARD, DROPOUT, MAX_SEQ_LEN)
    
    # Load pre-trained model if it exists
    if os.path.exists(MODEL_PATH):
        print(f"Loading pre-trained model from {MODEL_PATH}")
        model.load_state_dict(torch.load(MODEL_PATH))
    else:
        print("No pre-trained model found. Starting training from scratch.")

    optimizer = torch.optim.Adam(model.parameters(), lr=LEARNING_RATE)
    criterion = nn.CrossEntropyLoss(ignore_index=VOCABULARY["<PAD>"]) # Ignore padding in loss calculation

    # Training loop
    model.train()
    for epoch in range(NUM_EPOCHS):
        total_loss = 0
        for batch in dataloader:
            # Input is all tokens except the last one
            src = batch[:, :-1]
            # Target is all tokens except the first one
            tgt = batch[:, 1:]

            optimizer.zero_grad()
            output = model(src) # (batch_size, seq_len-1, vocab_size)

            # Reshape for CrossEntropyLoss: (N, C, d1, d2, ...)
            loss = criterion(output.reshape(-1, VOCAB_SIZE), tgt.reshape(-1))
            loss.backward()
            optimizer.step()
            total_loss += loss.item()

        print(f"Epoch {epoch+1}/{NUM_EPOCHS}, Loss: {total_loss / len(dataloader):.4f}")

    print("Training complete.")
    # Save the trained model
    torch.save(model.state_dict(), MODEL_PATH)
    print(f"Model saved to {MODEL_PATH}")

if __name__ == "__main__":
    train_transformer_model()
