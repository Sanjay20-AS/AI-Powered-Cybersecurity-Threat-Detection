"""Convenience entry point: train then run the sample detection scenario."""
from src.train import train
from src.detect import detect

if __name__ == "__main__":
    train()
    detect()
