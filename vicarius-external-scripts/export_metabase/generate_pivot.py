import os
import smtplib
import sys
from pathlib import Path

from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import pandas as pd


BASE_DIR = Path(__file__).resolve().parent
SHARED_HELPERS_DIR = BASE_DIR.parent
if str(SHARED_HELPERS_DIR) not in sys.path:
    sys.path.insert(0, str(SHARED_HELPERS_DIR))

from postgres_connection import connect_postgres


CSV_OUTPUT_PATH = BASE_DIR / "dados_assets.csv"
ENV_CANDIDATES = [
    BASE_DIR.parent.parent / ".env",
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
PIVOT_SHEET_TITLES = {
    "Fabricante": "Assets com Patches Pendentes por Fabricante",
    "Fabricante+Asset": "Patches Pendentes por Asset do Fabricante",
    "Assets": "Patches Pendentes por Assets",
    "Assets+Patches": "Patch Pendente por Asset (1: Pendente - 0: Concluído)",
    "Filial": "Assets com Patches Pendentes por Filial",
    "Filial+Patches": "Assets com o Patch Pendente Patch da Filial",
    "Sensibilidade": "Patches Pendentes por Sensibilidade",
    "Sensibilidade+Patches": "Assets com o Patch Pendente por Sensibilidade",
}
SYNTHETIC_SHEET_NAME = "Dados Sintéticos"


def load_env_local(env_paths):
    loaded_values = {}

    for env_path in env_paths:
        if not env_path.exists():
            continue

        with open(env_path, "r", encoding="utf-8") as env_file:
            for line in env_file:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                loaded_values[key.strip()] = value.strip().strip('"').strip("'")

    for key, value in loaded_values.items():
        os.environ.setdefault(key, value)


def get_smtp_config():
    load_env_local(ENV_CANDIDATES)

    config = {
        "host": os.environ.get("SMTP_HOST", "").strip(),
        "port": os.environ.get("SMTP_PORT", "587").strip(),
        "user": os.environ.get("SMTP_USER", "").strip(),
        "password": os.environ.get("SMTP_PASSWORD", "").strip(),
        "from_address": os.environ.get("SMTP_FROM", "").strip(),
        "use_tls": os.environ.get("SMTP_USE_TLS", "true").strip().lower() == "true",
    }

    missing_keys = [
        env_name
        for env_name, value in {
            "SMTP_HOST": config["host"],
            "SMTP_PORT": config["port"],
            "SMTP_USER": config["user"],
            "SMTP_PASSWORD": config["password"],
            "SMTP_FROM": config["from_address"],
        }.items()
        if not value
    ]
    if missing_keys:
        raise RuntimeError(
            "Configuração de SMTP incompleta. Defina as variáveis: "
            + ", ".join(missing_keys)
        )

    return config


def parse_email_recipients(emails_value):
    if emails_value is None:
        return []

    recipients = []
    for raw_email in str(emails_value).split(";"):
        email = raw_email.strip()
        if not email:
            continue
        if "@" not in email or "." not in email.rsplit("@", 1)[-1]:
            print(f"Aviso: email inválido ignorado: {email}")
            continue
        if email not in recipients:
            recipients.append(email)

    return recipients


def format_subject_date(value):
    if hasattr(value, "strftime"):
        return value.strftime("%d/%m/%Y")

    return str(value)


def format_filename_date(value):
    if hasattr(value, "strftime"):
        return value.strftime("%Y%m%d")

    return str(value).strip().replace("-", "").replace("/", "")


def build_excel_output_path(data_inicio, data_fim):
    file_name = (
        "patch-tuesday_"
        f"{format_filename_date(data_inicio)}-"
        f"{format_filename_date(data_fim)}.xlsx"
    )
    return BASE_DIR / file_name


def send_excel_by_email(recipients, excel_path, data_inicio, data_fim):
    if not recipients:
        print("Nenhum destinatário válido encontrado; XLSX gerado sem envio por email.")
        return

    smtp_config = get_smtp_config()

    message = MIMEMultipart()
    message["From"] = smtp_config["from_address"]
    message["To"] = ", ".join(recipients)
    message["Subject"] = (
        "Vicarius - Relatório de Evolução dos Patches - "
        f"{format_subject_date(data_inicio)} à {format_subject_date(data_fim)}"
    )
    message.attach(
        MIMEText(
            f"Olá,\n\nSegue em anexo o arquivo {Path(excel_path).name} gerado automaticamente.\n",
            "plain",
            "utf-8",
        )
    )

    with open(excel_path, "rb") as attachment_file:
        attachment = MIMEBase(
            "application",
            "vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
        attachment.set_payload(attachment_file.read())

    encoders.encode_base64(attachment)
    attachment.add_header(
        "Content-Disposition",
        f'attachment; filename="{Path(excel_path).name}"',
    )
    message.attach(attachment)

    with smtplib.SMTP(smtp_config["host"], int(smtp_config["port"])) as server:
        if smtp_config["use_tls"]:
            server.starttls()
        server.login(smtp_config["user"], smtp_config["password"])
        server.sendmail(
            smtp_config["from_address"],
            recipients,
            message.as_string(),
        )

    print(f"Email com XLSX enviado para: {', '.join(recipients)}")


def fetch_control_row(connection):
    query = """
        SELECT data_inicio, data_fim, emails
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

    data_inicio, data_fim, emails = rows[0]
    if data_inicio is None or data_fim is None:
        raise RuntimeError(
            "O registro de public.pivot_assets precisa conter data_inicio e data_fim preenchidos."
        )

    return {
        "data_inicio": data_inicio,
        "data_fim": data_fim,
        "emails": emails,
    }


def fetch_pivot_dataframe(connection):
    query = "SELECT * FROM public.mvw_pivot_assets;"

    with connection.cursor() as cursor:
        cursor.execute(query)
        rows = cursor.fetchall()
        columns = [description[0] for description in cursor.description]

    return pd.DataFrame(rows, columns=columns)


def refresh_dataset_from_database():
    with connect_postgres(env_paths=ENV_CANDIDATES) as connection:
        control_row = fetch_control_row(connection)
        print(
            "Registro de controle encontrado: "
            f"data_inicio={control_row['data_inicio']}, "
            f"data_fim={control_row['data_fim']}"
        )

        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT criar_mview_pivot_assets(%s, %s);",
                (control_row["data_inicio"], control_row["data_fim"]),
            )

        connection.commit()
        df = fetch_pivot_dataframe(connection)

    df.to_csv(CSV_OUTPUT_PATH, index=False)
    print(f"CSV atualizado com {len(df)} registros em {CSV_OUTPUT_PATH}")
    return df, control_row


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


def format_header_text(value):
    if value is None:
        return ""

    return str(value).strip().upper()


def build_export_dataframe(dataframe):
    export_df = dataframe.reset_index()
    export_df.columns = [format_header_text(column) for column in export_df.columns]
    return export_df


def build_excel(df, excel_output_path, synthetic_df=None):
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

    with pd.ExcelWriter(excel_output_path, engine="xlsxwriter") as writer:
        workbook = writer.book
        header_fmt = workbook.add_format(
            {
                "bold": True,
                "font_color": "#FFFFFF",
                "bg_color": "#000000",
                "border": 1,
                "align": "center",
                "valign": "vcenter",
            }
        )
        content_fmt = workbook.add_format({"border": 1})
        total_fmt = workbook.add_format({"bold": True, "bg_color": "#D9D9D9", "border": 1})
        title_fmt = workbook.add_format(
            {
                "bold": True,
                "font_size": 20,
                "align": "left",
                "valign": "vcenter",
            }
        )

        evolution_header_fmt = workbook.add_format(
            {
                "bold": True,
                "font_color": "#FFFFFF",
                "align": "center",
                "valign": "vcenter",
            }
        )
        evolution_content_fmt = workbook.add_format({"font_color": "#FFFFFF"})
        evolution_total_fmt = workbook.add_format({"bold": True, "font_color": "#FFFFFF"})

        def write_dataframe(
            ws,
            dataframe,
            startrow=0,
            add_total=False,
            title=None,
            format_headers=True,
            title_format=None,
            header_format=None,
            content_format=None,
            total_format=None,
        ):
            export_df = dataframe.copy()
            if format_headers:
                export_df.columns = [format_header_text(column) for column in export_df.columns]

            resolved_title_fmt = title_format or title_fmt
            resolved_header_fmt = header_format or header_fmt
            resolved_content_fmt = content_format or content_fmt
            resolved_total_fmt = total_format or total_fmt

            if title:
                last_column = max(len(export_df.columns) - 1, 0)
                if last_column > 0:
                    ws.merge_range(0, 0, 0, last_column, title, resolved_title_fmt)
                else:
                    ws.write(0, 0, title, resolved_title_fmt)
                ws.set_row(0, 30)

            for col_idx, column_name in enumerate(export_df.columns):
                ws.write(startrow, col_idx, column_name, resolved_header_fmt)

            for row_offset, row_values in enumerate(export_df.itertuples(index=False), start=1):
                for col_idx, cell_value in enumerate(row_values):
                    if pd.isna(cell_value):
                        cell_value = ""
                    ws.write(startrow + row_offset, col_idx, cell_value, resolved_content_fmt)

            last_data_row = startrow + len(export_df)
            if add_total:
                numeric_columns = export_df.select_dtypes(include="number").columns
                for col_idx, column_name in enumerate(export_df.columns):
                    if col_idx == 0:
                        value = "TOTAL"
                    elif column_name in numeric_columns:
                        value = export_df[column_name].sum()
                    else:
                        value = ""
                    ws.write(last_data_row + 1, col_idx, value, resolved_total_fmt)
                final_row = last_data_row + 1
            else:
                final_row = last_data_row

            for col_idx, column_name in enumerate(export_df.columns):
                column_values = export_df.iloc[:, col_idx].astype(str).tolist()
                max_length = max([len(column_name), *[len(value) for value in column_values]]) if column_values else len(column_name)
                ws.set_column(col_idx, col_idx, min(max_length + 2, 40))

            return {
                "header_row": startrow,
                "first_data_row": startrow + 1,
                "last_data_row": startrow + len(export_df),
                "final_row": final_row,
            }

        evolution_sheet_name = "Evolução dos Patches"
        ws_chart = workbook.add_worksheet(evolution_sheet_name)
        writer.sheets[evolution_sheet_name] = ws_chart

        total_por_dia_export = total_por_dia.copy()
        evolucao_fabricante_export = evolucao_fabricante.copy()
        evolucao_fabricante_export.columns = [
            evolucao_fabricante_export.columns[0],
            *[format_header_text(column) for column in evolucao_fabricante_export.columns[1:]],
        ]

        total_table_info = write_dataframe(
            ws_chart,
            total_por_dia_export,
            startrow=20,
            add_total=True,
            header_format=evolution_header_fmt,
            content_format=evolution_content_fmt,
            total_format=evolution_total_fmt,
        )
        fabricante_table_start = total_table_info["final_row"] + 3
        fabricante_table_info = write_dataframe(
            ws_chart,
            evolucao_fabricante_export,
            startrow=fabricante_table_start,
            add_total=False,
            header_format=evolution_header_fmt,
            content_format=evolution_content_fmt,
            total_format=evolution_total_fmt,
        )

        # Exporta pivots principais
        for sheet_name, pivot in [
            ("Fabricante", pivot_fabricante),
            ("Fabricante+Asset", pivot_fabricante_asset),
            ("Assets", pivot_assets),
            ("Assets+Patches", pivot_assets_patches),
            ("Filial", pivot_filial),
            ("Filial+Patches", pivot_filial_patches),
            ("Sensibilidade", pivot_sensibilidade),
            ("Sensibilidade+Patches", pivot_sensibilidade_patches),
        ]:
            ws = workbook.add_worksheet(sheet_name)
            writer.sheets[sheet_name] = ws
            write_dataframe(
                ws,
                build_export_dataframe(pivot),
                startrow=2,
                add_total=True,
                title=PIVOT_SHEET_TITLES.get(sheet_name),
            )

        # Gráfico total por dia
        chart_total = workbook.add_chart({"type": "line"})
        if chart_total is None:
            raise RuntimeError("Falha ao criar o gráfico de total por dia.")
        chart_total.add_series({
            "name": "Total de Patches",
            "categories": [
                evolution_sheet_name,
                total_table_info["first_data_row"],
                0,
                total_table_info["last_data_row"],
                0,
            ],
            "values": [
                evolution_sheet_name,
                total_table_info["first_data_row"],
                1,
                total_table_info["last_data_row"],
                1,
            ],
        })
        chart_total.set_title({"name": "Evolução do Total de Patches"})
        chart_total.set_style(2)
        ws_chart.insert_chart(1, 1, chart_total)

        # Gráfico por Fabricante
        chart_fabricante = workbook.add_chart({"type": "line"})
        if chart_fabricante is None:
            raise RuntimeError("Falha ao criar o gráfico por fabricante.")
        for i, fabricante in enumerate(evolucao_fabricante.columns[1:]):  # ignora coluna data_dia
            chart_fabricante.add_series({
                "name": fabricante,
                "categories": [
                    evolution_sheet_name,
                    fabricante_table_info["first_data_row"],
                    0,
                    fabricante_table_info["last_data_row"],
                    0,
                ],
                "values": [
                    evolution_sheet_name,
                    fabricante_table_info["first_data_row"],
                    i + 1,
                    fabricante_table_info["last_data_row"],
                    i + 1,
                ],
            })
        chart_fabricante.set_title({"name": "Evolução por Fabricante"})
        chart_fabricante.set_style(10)
        ws_chart.insert_chart(1, 9, chart_fabricante)

        if CSV_OUTPUT_PATH.exists():
            synthetic_export_df = pd.read_csv(CSV_OUTPUT_PATH, na_filter=False)
        elif synthetic_df is not None:
            synthetic_export_df = synthetic_df.copy()
        else:
            synthetic_export_df = df.copy()
        ws_synthetic = workbook.add_worksheet(SYNTHETIC_SHEET_NAME)
        writer.sheets[SYNTHETIC_SHEET_NAME] = ws_synthetic
        write_dataframe(
            ws_synthetic,
            synthetic_export_df,
            startrow=2,
            add_total=False,
            title=SYNTHETIC_SHEET_NAME,
            format_headers=True,
        )

    print(f"Arquivo Excel atualizado em {excel_output_path}")


def main():
    df, control_row = refresh_dataset_from_database()
    prepared_df = prepare_dataframe(df)
    excel_output_path = build_excel_output_path(
        control_row.get("data_inicio"),
        control_row.get("data_fim"),
    )
    build_excel(prepared_df, excel_output_path, synthetic_df=df)
    recipients = parse_email_recipients(control_row.get("emails"))
    send_excel_by_email(
        recipients,
        excel_output_path,
        control_row.get("data_inicio"),
        control_row.get("data_fim"),
    )


if __name__ == "__main__":
    main()
