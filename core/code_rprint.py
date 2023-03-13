# coding:utf-8
from rich import print as rprint

def error(date, body):
    rprint("[[bold green]" + date + "[/bold green]] [[bold red]Error[/bold red]] > [bold yellow]" + body + "[/bold yellow]")

def success(date, body):
    rprint("[[bold green]" + date + "[/bold green]] [[bold green]Success[/bold green]] > " + body)

def info(date, body):
    rprint("[[bold green]" + date + "[/bold green]] [[bold blue]Info[/bold blue]] > " + body)