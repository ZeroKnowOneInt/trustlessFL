"""666-parameter FMNIST example for the generic user-model adapter."""
import torch


def make_model(channels=(4, 8), classes=10):
    first, second = channels
    return torch.nn.Sequential(
        torch.nn.Conv2d(1, first, 3, padding=1), torch.nn.ReLU(), torch.nn.MaxPool2d(2),
        torch.nn.Conv2d(first, second, 3, padding=1), torch.nn.ReLU(),
        torch.nn.AdaptiveAvgPool2d((2, 2)), torch.nn.Flatten(),
        torch.nn.Linear(second*2*2, classes))


def prepare_inputs(x):
    # Same input normalization as the existing FMNIST workload; all state is public/fixed.
    return (torch.from_numpy(x).float().unsqueeze(1)/255.0-.1307)/.3081
