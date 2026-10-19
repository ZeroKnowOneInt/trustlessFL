"""Replace make_model/prepare_inputs with a self-contained user classifier."""
import torch


def make_model(input_features=6, hidden=5, classes=3):
    return torch.nn.Sequential(torch.nn.Linear(input_features, hidden), torch.nn.ReLU(),
                               torch.nn.Linear(hidden, classes))


def prepare_inputs(x):
    return torch.from_numpy(x).float()
