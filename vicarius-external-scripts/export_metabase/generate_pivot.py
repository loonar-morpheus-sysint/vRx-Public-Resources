import os
from pathlib import Path

import pandas as pd
import psycopg2


BASE_DIR = Path(__file__).resolve().parent
CSV_OUTPUT_PATH = BASE_DIR / "dados_assets.csv"
EXCEL_OUTPUT_PATH = BASE_DIR / "pivot_assets.xlsx"
ENV_CANDIDATES = [
    BASE_DIR.parent / ".env",
    BASE_DIR / ".env",
]
REQUIRED_COLUMNS = {
    "filial",
    "sensibilidade",
    "asset_name",
    "patch_name",
    "fabricante",
    "data_dia",
    "quantidade",
}


def load_env_local(env_paths):
    for env_path in env_paths:
        if not env_path.exists():
            continue

        with open(env_path, "r", encoding="utf-8") as env_file:
            for line in env_file:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def get_db_config():
    load_env_local(ENV_CANDIDATES)

    config = {
        "host": os.environ.get("PGHOST", "").strip(),
        "port": os.environ.get("PGPORT", "5432").strip(),
        "dbname": os.environ.get("PGDATABASE", "").strip(),
        "user": os.environ.get("PGUSER", "").strip(),
        "password": os.environ.get("PGPASSWORD", os.environ.get("PGPASS", "")).strip(),
    }

    missing_keys = [
        env_name
        for env_name, value in {
            "PGHOST": config["host"],
            "PGDATABASE": config["dbname"],
            "PGUSER": config["user"],
            "PGPASSWORD ou PGPASS": config["password"],
        }.items()
        if not value
    ]
    if missing_keys:
        raise RuntimeError(
            "Configuração do PostgreSQL incompleta. Defina as variáveis: "
            + ", ".join(missing_keys)
        )

    return config


def fetch_control_row(connection):
    query = """
        SELECT nome_onda, data_inicio, data_fim
        FROM public.pivot_assets
        LIMIT 2;
    """

    with connection.cursor() as cursor:
        cursor.execute(query)
        rows = cursor.fetchall()

    if not rows:
        raise RuntimeError("Nenhum registro encontrado em public.pivot_assets.")
    if len(rows) > 1:
        raise RuntimeError(
            "Foram encontrados múltiplos registros em public.pivot_assets; "
            "o script espera exatamente um registro."
        )

    nome_onda, data_inicio, data_fim = rows[0]
    if data_inicio is None or data_fim is None:
        raise RuntimeError(
            "O registro de public.pivot_assets precisa conter data_inicio e data_fim preenchidos."
        )

    return {
        "nome_onda": nome_onda,
        "data_inicio": data_inicio,
        "data_fim": data_fim,
    }


def refresh_dataset_from_database():
    db_config = get_db_config()

    with psycopg2.connect(**db_config) as connection:
        control_row = fetch_control_row(connection)
        print(
            "Registro de controle encontrado: "
            f"nome_onda={control_row['nome_onda']}, "
            f"data_inicio={control_row['data_inicio']}, "
            f"data_fim={control_row['data_fim']}"
        )

        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT criar_mview_pivot_assets(%s, %s);",
                (control_row["data_inicio"], control_row["data_fim"]),
            )

        df = pd.read_sql_query("SELECT * FROM public.mvw_pivot_assets;", connection)

    df.to_csv(CSV_OUTPUT_PATH, index=False)
    print(f"CSV atualizado com {len(df)} registros em {CSV_OUTPUT_PATH}")
    return df


def prepare_dataframe(df):
    missing_columns = sorted(REQUIRED_COLUMNS - set(df.columns))
    if missing_columns:
        raise RuntimeError(
            "A consulta em public.mvw_pivot_assets não retornou as colunas esperadas: "
            + ", ".join(missing_columns)
        )

    prepared_df = df.copy()
    prepared_df["sensibilidade"] = prepared_df["sensibilidade"].fillna("N/A")
    prepared_df["sensibilidade"] = prepared_df["sensibilidade"].astype(str).str.strip().str.upper()
    prepared_df["fabricante"] = prepared_df["fabricante"].fillna("N/A").astype(str).str.strip().str.upper()
    prepared_df["filial"] = prepared_df["filial"].fillna("N/A").astype(str).str.strip().str.upper()
    prepared_df["asset_name"] = prepared_df["asset_name"].fillna("N/A").astype(str).str.strip().str.upper()
    prepared_df["patch_name"] = prepared_df["patch_name"].fillna("N/A").astype(str).str.strip()
    prepared_df["data_dia"] = prepared_df["data_dia"].astype(str).str.strip()
    prepared_df["quantidade"] = pd.to_numeric(prepared_df["quantidade"], errors="coerce").fillna(0)

    return prepared_df


def build_excel(df):
    # --- Pivots ---
    pivot_fabricante = pd.pivot_table(df, values="quantidade", index=["fabricante"],
                                      columns="data_dia", aggfunc="sum", fill_value=0)

    pivot_fabricante_asset = pd.pivot_table(df, values="quantidade", index=["fabricante", "asset_name"],
                                            columns="data_dia", aggfunc="sum", fill_value=0)

    pivot_assets = pd.pivot_table(df, values="quantidade", index=["asset_name"],
                                  columns="data_dia", aggfunc="sum", fill_value=0)

    pivot_assets_patches = pd.pivot_table(df, values="quantidade", index=["asset_name", "patch_name"],
                                          columns="data_dia", aggfunc="sum", fill_value=0)

    pivot_filial = pd.pivot_table(df, values="quantidade", index=["filial"],
                                  columns="data_dia", aggfunc="sum", fill_value=0)

    pivot_filial_patches = pd.pivot_table(df, values="quantidade", index=["filial", "patch_name"],
                                          columns="data_dia", aggfunc="sum", fill_value=0)

    pivot_sensibilidade = pd.pivot_table(df, values="quantidade", index=["sensibilidade"],
                                         columns="data_dia", aggfunc="sum", fill_value=0)

    pivot_sensibilidade_patches = pd.pivot_table(df, values="quantidade", index=["sensibilidade", "patch_name"],
                                                 columns="data_dia", aggfunc="sum", fill_value=0)

    # Totais por dia
    total_por_dia = df.groupby("data_dia")["quantidade"].sum().reset_index()

    # Evolução por Fabricante (pivotada para tabela)
    evolucao_fabricante = pd.pivot_table(df, values="quantidade", index="data_dia",
                                         columns="fabricante", aggfunc="sum", fill_value=0).reset_index()

    with pd.ExcelWriter(EXCEL_OUTPUT_PATH, engine="xlsxwriter") as writer:
        # Exporta pivots principais
        pivot_fabricante.to_excel(writer, sheet_name="Fabricante")
        pivot_fabricante_asset.to_excel(writer, sheet_name="Fabricante+Asset")
        pivot_assets.to_excel(writer, sheet_name="Assets")
        pivot_assets_patches.to_excel(writer, sheet_name="Assets+Patches")
        pivot_filial.to_excel(writer, sheet_name="Filial")
        pivot_filial_patches.to_excel(writer, sheet_name="Filial+Patches")
        pivot_sensibilidade.to_excel(writer, sheet_name="Sensibilidade")
        pivot_sensibilidade_patches.to_excel(writer, sheet_name="Sensibilidade+Patches")

        # Aba Evolução_Patches: primeiro gráficos, depois tabelas
        total_por_dia.to_excel(writer, sheet_name="Evolução_Patches", startrow=20, index=False)
        evolucao_fabricante.to_excel(writer, sheet_name="Evolução_Patches", startrow=20 + len(total_por_dia) + 3, index=False)

        workbook = writer.book
        total_fmt = workbook.add_format({"bold": True, "bg_color": "#D9D9D9"})

        def add_totalizer(ws, pivot, startrow=1):
            nrows, ncols = pivot.shape
            ws.write(nrows + startrow, 0, "TOTAL", total_fmt)
            for j in range(ncols):
                ws.write(nrows + startrow, j + 1, pivot.iloc[:, j].sum(), total_fmt)

        # Ajusta colunas + totalizadores
        for sheet_name, pivot in [
            ("Fabricante", pivot_fabricante),
            ("Fabricante+Asset", pivot_fabricante_asset),
            ("Assets", pivot_assets),
            ("Assets+Patches", pivot_assets_patches),
            ("Filial", pivot_filial),
            ("Filial+Patches", pivot_filial_patches),
            ("Sensibilidade", pivot_sensibilidade),
            ("Sensibilidade+Patches", pivot_sensibilidade_patches)
        ]:
            ws = writer.sheets[sheet_name]
            for i, col in enumerate(pivot.columns.insert(0, pivot.index.name)):
                ws.set_column(i, i, 15)
            add_totalizer(ws, pivot)

        # Gráficos na aba Evolução_Patches
        ws_chart = writer.sheets["Evolução_Patches"]

        # Gráfico total por dia
        chart_total = workbook.add_chart({"type": "line"})
        chart_total.add_series({
            "name": "Total de Patches",
            "categories": ["Evolução_Patches", 21, 0, 20 + len(total_por_dia), 0],
            "values": ["Evolução_Patches", 21, 1, 20 + len(total_por_dia), 1],
        })
        chart_total.set_title({"name": "Evolução do Total de Patches"})
        chart_total.set_style(2)
        ws_chart.insert_chart("B2", chart_total)

        # Gráfico por Fabricante
        chart_fabricante = workbook.add_chart({"type": "line"})
        base_row = 20 + len(total_por_dia) + 4
        for i, fabricante in enumerate(evolucao_fabricante.columns[1:]):  # ignora coluna data_dia
            chart_fabricante.add_series({
                "name": fabricante,
                "categories": ["Evolução_Patches", base_row, 0,
                               base_row + len(evolucao_fabricante) - 1, 0],
                "values": ["Evolução_Patches", base_row, i + 1,
                           base_row + len(evolucao_fabricante) - 1, i + 1],
            })
        chart_fabricante.set_title({"name": "Evolução por Fabricante"})
        chart_fabricante.set_style(10)
        ws_chart.insert_chart("J2", chart_fabricante)

        # Totalizador geral na aba Evolução_Patches
        ws_chart.write(20 + len(total_por_dia) + 1, 0, "TOTAL", total_fmt)
        ws_chart.write(20 + len(total_por_dia) + 1, 1, total_por_dia["quantidade"].sum(), total_fmt)

    print(f"Arquivo Excel atualizado em {EXCEL_OUTPUT_PATH}")


def main():
    df = refresh_dataset_from_database()
    prepared_df = prepare_dataframe(df)
    build_excel(prepared_df)


if __name__ == "__main__":
    main()
