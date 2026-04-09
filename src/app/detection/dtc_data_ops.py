import os
from typing import List

import pandas as pd


class DtcDataOperations:
    def __init__(self):
        self.input_dataset_file_path = "src/res/datasets/combined.csv"  # raw dataset path
        self.input_dataset_info_file_path = "src/outputs/datasets/detection/input_dataset_info.txt"
        self.output_dataset_file_path = "src/outputs/datasets/detection/combined_output.csv"
        self.output_dataset_info_file_path = "src/outputs/datasets/detection/output_dataset_info.txt"

        for path in [
            self.input_dataset_file_path,
            self.input_dataset_info_file_path,
            self.output_dataset_file_path,
            self.output_dataset_info_file_path,
        ]:
            os.makedirs(os.path.dirname(path), exist_ok=True)

        self.df = pd.read_csv(self.input_dataset_file_path)

    def dataAnalysis(self, file_path: str) -> None:
        total_records = len(self.df)
        label_counts = self.df["Label"].value_counts(dropna=False) if "Label" in self.df.columns else {}
        columns_info = self.df.dtypes

        with open(file_path, "w", encoding="utf-8") as f:
            f.write("General Dataset Information\n")
            f.write(f"Total number of records: {total_records}\n\n")

            f.write("Label Distribution\n")
            if len(label_counts) > 0:
                for label, count in label_counts.items():
                    f.write(f"{label}: {count} ({count / total_records * 100:.2f}%)\n")
            else:
                f.write("Label column not found.\n")

            f.write("\nColumn Data Types\n")
            for col, dtype in columns_info.items():
                f.write(f"{col}: {dtype}\n")

        print(f"Data analysis saved in file '{file_path}'.")

    @staticmethod
    def _safe_numeric(series: pd.Series) -> pd.Series:
        return pd.to_numeric(series, errors="coerce").fillna(0.0)

    def _validate_required_columns(self, required_columns: List[str]) -> None:
        missing_columns = [col for col in required_columns if col not in self.df.columns]
        if missing_columns:
            raise ValueError(
                f"The following required columns were not found in file "
                f"'{self.input_dataset_file_path}': {missing_columns}"
            )

    def _prepare_base_columns(self) -> None:
        required_columns = [
            "Proto",
            "Dur",
            "TotBytes",
            "SrcBytes",
            "DstBytes",
            "TotPkts",
            "SrcPkts",
            "DstPkts",
            "Label",
        ]
        self._validate_required_columns(required_columns)

        # Sayısal kolonları güvenli biçimde normalize et
        numeric_columns = [
            "Dur",
            "TotBytes",
            "SrcBytes",
            "DstBytes",
            "TotPkts",
            "SrcPkts",
            "DstPkts",
        ]
        for col in numeric_columns:
            self.df[col] = self._safe_numeric(self.df[col])

        # Proto standardizasyonu
        self.df["Proto"] = self.df["Proto"].astype(str).str.lower().fillna("unknown")

    def _derive_features(self) -> None:
        dur = self.df["Dur"]
        tot_bytes = self.df["TotBytes"]
        src_bytes = self.df["SrcBytes"]
        dst_bytes = self.df["DstBytes"]
        tot_pkts = self.df["TotPkts"]
        src_pkts = self.df["SrcPkts"]
        dst_pkts = self.df["DstPkts"]

        dur_pos = dur.where(dur > 0)
        tot_pkts_pos = tot_pkts.where(tot_pkts > 0)
        src_pkts_pos = src_pkts.where(src_pkts > 0)
        dst_pkts_pos = dst_pkts.where(dst_pkts > 0)
        tot_bytes_pos = tot_bytes.where(tot_bytes > 0)

        self.df["BytesPerSec"] = (tot_bytes / dur_pos).fillna(0.0)
        self.df["PktsPerSec"] = (tot_pkts / dur_pos).fillna(0.0)

        self.df["SrcBytesPerSec"] = (src_bytes / dur_pos).fillna(0.0)
        self.df["DstBytesPerSec"] = (dst_bytes / dur_pos).fillna(0.0)

        self.df["SrcPktsPerSec"] = (src_pkts / dur_pos).fillna(0.0)
        self.df["DstPktsPerSec"] = (dst_pkts / dur_pos).fillna(0.0)

        self.df["MeanPktSz"] = (tot_bytes / tot_pkts_pos).fillna(0.0)
        self.df["SrcMeanPktSz"] = (src_bytes / src_pkts_pos).fillna(0.0)
        self.df["DstMeanPktSz"] = (dst_bytes / dst_pkts_pos).fillna(0.0)

        self.df["SrcByteShare"] = (src_bytes / tot_bytes_pos).fillna(0.0)
        self.df["DstByteShare"] = (dst_bytes / tot_bytes_pos).fillna(0.0)

        self.df["SrcPktShare"] = (src_pkts / tot_pkts_pos).fillna(0.0)
        self.df["DstPktShare"] = (dst_pkts / tot_pkts_pos).fillna(0.0)

    def filterData(self) -> pd.DataFrame:
        # İstenirse belirli saldırı tipi dışarı alınır
        if "Attack Type" in self.df.columns:
            self.df = self.df[self.df["Attack Type"] != "UDPScan"].copy()

        self._prepare_base_columns()
        self._derive_features()

        selected_columns = [
            "Proto",
            "Dur",
            "TotBytes",
            "SrcBytes",
            "DstBytes",
            "TotPkts",
            "SrcPkts",
            "DstPkts",
            "BytesPerSec",
            "PktsPerSec",
            "SrcBytesPerSec",
            "DstBytesPerSec",
            "SrcPktsPerSec",
            "DstPktsPerSec",
            "MeanPktSz",
            "SrcMeanPktSz",
            "DstMeanPktSz",
            "SrcByteShare",
            "DstByteShare",
            "SrcPktShare",
            "DstPktShare",
            "Label",
        ]

        self.df = self.df[selected_columns].copy()
        self.df.to_csv(self.output_dataset_file_path, index=False, encoding="utf-8")
        print(f"Selected columns are saved in file '{self.output_dataset_file_path}'.")

        return self.df

    def allSteps(self) -> None:
        self.dataAnalysis(self.input_dataset_info_file_path)
        self.filterData()
        self.dataAnalysis(self.output_dataset_info_file_path)


if __name__ == "__main__":
    ops = DtcDataOperations()
    ops.allSteps()