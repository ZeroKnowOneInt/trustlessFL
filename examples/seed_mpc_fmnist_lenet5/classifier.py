"""The existing 61,706-parameter FMNIST LeNet5 through the generic adapter."""
from trustlessfl.fmnist import make_model as lenet5, tensor_images


def make_model():
    return lenet5()


def prepare_inputs(x):
    return tensor_images(x,'cpu')
