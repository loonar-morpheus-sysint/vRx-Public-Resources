import subprocess
import sys
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
SHARED_HELPERS_DIR = BASE_DIR.parent
if str(SHARED_HELPERS_DIR) not in sys.path:
    sys.path.insert(0, str(SHARED_HELPERS_DIR))

from postgres_connection import connect_postgres


ENV_CANDIDATES = [
    BASE_DIR.parent.parent / ".env",
    BASE_DIR.parent / ".env",
    BASE_DIR / ".env",
]
GENERATE_PIVOT_PATH = BASE_DIR / "generate_pivot.py"


def should_generate_immediately(connection):
    query = """
        SELECT EXISTS(
            SELECT 1
            FROM public.pivot_assets
            WHERE gerar_imediatamente IS TRUE
        );
    """

    with connection.cursor() as cursor:
        cursor.execute(query)
        result = cursor.fetchone()

    return bool(result[0]) if result else False


def disable_immediate_generation(connection):
    query = """
        UPDATE public.pivot_assets
        SET gerar_imediatamente = FALSE
        WHERE gerar_imediatamente IS TRUE;
    """

    with connection.cursor() as cursor:
        cursor.execute(query)

    connection.commit()


def execute_generate_pivot():
    if not GENERATE_PIVOT_PATH.exists():
        raise FileNotFoundError(f"Script não encontrado: {GENERATE_PIVOT_PATH}")

    subprocess.run([sys.executable, str(GENERATE_PIVOT_PATH)], check=True)


def main():
    with connect_postgres(env_paths=ENV_CANDIDATES) as connection:
        if not should_generate_immediately(connection):
            print("Campo gerar_imediatamente está false; nenhuma execução foi iniciada.")
            return

        disable_immediate_generation(connection)
        print("Campo gerar_imediatamente alterado para false.")

    print("Executando generate_pivot.py...")
    execute_generate_pivot()


if __name__ == "__main__":
    main()
