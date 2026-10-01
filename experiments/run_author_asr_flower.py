"""CLI compatibility entrypoint for the author ASR Flower source port."""

from trustlessfl.aion_source_server import AuthorASRWorkflow, app, cli, provision_source


if __name__ == "__main__":
    cli()
