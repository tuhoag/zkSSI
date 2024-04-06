import argparse
import glob
import json
import logging
import os
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import matplotlib.lines as mlines

logger = logging.getLogger(__name__)

OFF_CHAIN_VER = "offchain-verify"
ON_CHAIN_VER = "onchain-verify"
OFF_CHAIN_PROVE = "offchain-prove"

def add_arguments(parser):
    parser.add_argument("--exp")

def str2log_mode(value):
    if value is None:
        return None

    if value in ["d", "debug", "10"]:
        log_mode = logging.DEBUG
    elif value in ["i", "info", "20"]:
        log_mode = logging.INFO
    elif value in ["w", "warning", "30"]:
        log_mode = logging.WARNING
    else:
        raise argparse.ArgumentTypeError("Unsupported log mode type: {}".format(value))

    return log_mode

def setup_arguments(add_arguments_fn):
    parser = argparse.ArgumentParser(description="Process some integers.")

    parser.add_argument("--log", type=str2log_mode, default=logging.INFO)
    add_arguments_fn(parser)

    args, _ = parser.parse_known_args()

    params = {}
    for arg in vars(args):
        params[arg] = getattr(args, arg)

    # os.environ[ASSERTION_VARIABLE] = params["assert"]

    return params

def setup_console_logging(args):
    level = args["log"]

    logger = logging.getLogger("")
    logger.setLevel(level)

    formatter = logging.Formatter(
        "%(name)-12s[%(lineno)d]: %(funcName)s %(levelname)-8s %(message)s "
    )

    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)

    logger.addHandler(console_handler)


def find_exp_data_path(exp_name):
    myMap = {
        OFF_CHAIN_VER: "./data/offchain/*.json",
        OFF_CHAIN_PROVE: "./data/offchain/*.json",
        ON_CHAIN_VER: "./data/onchain-ver/*.json",
    }

    return myMap[exp_name]

def find_raw_report_data(exp_name):
    res = glob.glob(find_exp_data_path(exp_name))
    data = []

    for path in res:
        f = open(path)
        cur_data = json.load(f)
        data.extend(cur_data)

        f.close()

    return data


def aggregate_report_data(exp_name, data):
    df = pd.DataFrame(data)

    if exp_name in [OFF_CHAIN_PROVE, OFF_CHAIN_VER]:
        if exp_name == OFF_CHAIN_PROVE:
            df = df[df.step == "prove"]
        else:
            df = df[df.step == "verify"]

        # df.to_csv("{}.csv".format(exp_name))
        # group by name, step, client, tree height, num conditions
        agg_df = df.groupby(by=["name", "step", "client", "treeHeight", "numConditions"])
        agg_df = agg_df.aggregate({"executionTime": ["mean", "std"], "peakMemoryUsage": ["mean", "std"], "meanMemoryUsage": ["mean", "std"], "stdMemoryUsage": ["mean", "std"]})
        # agg_df = agg_df.drop(columns=["trial"])

        # print(agg_df)

        flat_cols = []


        # iterate through this tuples and
        # join them as single string
        for i in agg_df.columns:
            # print(i)
            flat_cols.append(i[0]+'_'+i[1])

        agg_df.columns = flat_cols
        agg_df = agg_df.reset_index()
        # agg_df.to_csv("agg_{}.csv".format(exp_name))

        df = agg_df

        df.sort_values(by=["name", "treeHeight", "numConditions", "client"], inplace=True)

    elif exp_name == ON_CHAIN_VER:
        df.sort_values(by=["mode", "treeHeight", "numConditions", "networkName"], inplace=True)
    else:
        raise Exception("Unsupported exp_name: {}".format(exp_name))


    df.to_csv("{}.csv".format(exp_name))

    return df

def save_figure(figure, path):
    if not os.path.exists(os.path.dirname(path)):
        os.makedirs(os.path.dirname(path))

    print("saving figure to: {}".format(path))
    figure.savefig(path)

def get_title(name):
    data = {
        "executionTime_meanS": "Execution Time (seconds)",
        "numConditions": "Conditions",
        "mode": "Mode",
        "treeHeight": "Revocation Tree Height",
        "peakMemoryUsage_mean": "Peak Memory (bytes)",
        "peakMemoryUsage_meanM": "Peak Memory (MBs)",
        "peakMemoryUsage_meanG": "Peak Memory (GBs)",
        "gasUsed": "Gas Consumption",
        "gasUsedK": "Gas Consumption (kGas)",
    }

    return data[name]

def modify_data(exp_name, df):


    if exp_name in [OFF_CHAIN_PROVE, OFF_CHAIN_VER]:
        df["executionTime_meanS"] = df["executionTime_mean"] / 1000

        df["peakMemoryUsage_meanM"] = df["peakMemoryUsage_mean"] / 1024 / 1024
        df["peakMemoryUsage_meanG"] = df["peakMemoryUsage_mean"] / 1024 / 1024 / 1024

        df["mode"] = df["name"]
        df["verifyTimeS"] = df["executionTime_meanS"]
        df["proveTimesS"] = df["executionTime_meanS"]
    else:
        df["modeId"] = df["mode"]
        df["gasUsedK"] = df["gasUsed"] / 1000
    #     df["algo_name"] = ""
    # df.loc[df[ALGO_KEY_COL]=="vac-ms", "algo_name"] = "PCKGA"
    # df.loc[df[ALGO_KEY_COL]=="hdbscan#max-kp", "algo_name"] = "CKGA(hdbscan)"
    # df.loc[df[ALGO_KEY_COL]=="km#max-kp", "algo_name"] = "CKGA(km)"

        df.loc[df["mode"] == 0, "mode"] = "SingleProof"
        df.loc[df["mode"] == 1, "mode"] = "MultiProof"


def visualize_data(exp_name, df):
    if exp_name == OFF_CHAIN_PROVE:
        visualize_offchain_prove(df)
    elif exp_name == OFF_CHAIN_VER:
        visualize_offchain_verify(df)
    elif exp_name == ON_CHAIN_VER:
        visualize_onchain_verify(df)

def visualize_onchain_verify(df):
    x_name = "numConditions"
    hue_cat_name = "mode"
    style_cat_name = "mode"
    network = "local"

    df = df[
            (df["treeHeight"] == 32) &
            # (df["mode"]=="MultiProof") &
            # (agg_df.numConditions <= 5) &
            (df["networkName"] == network)
        ]

    logger.info(df)

    time_fig_name = "onchain_verify-{}-{}".format("gasUsed", network)
    # memory_fig_name = "offchain_prove-{}-{}".format("peakMemoryUsage_meanM", client)

    # sns.barplot(data=df, x="numConditions", y="gasUsed", hue="mode")
    # plt.show()
    visualize_line_chart(df, x_name, "gasUsedK", hue_cat_name, style_cat_name, time_fig_name)

def visualize_offchain_verify(df):
    x_name = "numConditions"
    hue_cat_name = "treeHeight"
    style_cat_name = "mode"

    for client in ["noir_rs", "nargo"]:
        cur_df = df[
                # (df.step == step) &
                # (agg_df.name=="SingleProof") &
                # (agg_df.numConditions <= 5) &
                (df.client==client)
            ]

        time_fig_name = "offchain_prove-{}-{}".format("executionTime_meanS", client)
        memory_fig_name = "offchain_prove-{}-{}".format("peakMemoryUsage_meanG", client)

        visualize_line_chart(cur_df, x_name, "executionTime_meanS", hue_cat_name, style_cat_name, time_fig_name)
        visualize_line_chart(cur_df, x_name, "peakMemoryUsage_meanG", hue_cat_name, style_cat_name, memory_fig_name)

def visualize_offchain_prove(df):
    x_name = "numConditions"
    hue_cat_name = "treeHeight"
    style_cat_name = "mode"

    for client in ["noir_rs", "nargo"]:
        cur_df = df[
            # (df.step == step) &
            # (agg_df.name=="SingleProof") &
            # (agg_df.numConditions <= 5) &
            (df.client==client)
        ]

        time_fig_name = "offchain_prove-{}-{}".format("executionTime_meanS", client)
        memory_fig_name = "offchain_prove-{}-{}".format("peakMemoryUsage_meanG", client)

        visualize_line_chart(cur_df, x_name, "executionTime_meanS", hue_cat_name, style_cat_name, time_fig_name)
        visualize_line_chart(cur_df, x_name, "peakMemoryUsage_meanG", hue_cat_name, style_cat_name, memory_fig_name)

def visualize_line_chart(df, x_name, y_name, hue_cat_name, style_cat_name, fig_name):
    x_values = df[x_name].unique()
    hue_cat_values = df[hue_cat_name].unique()
    style_cat_values = df[style_cat_name].unique()

    palette = sns.color_palette("bright", len(hue_cat_values))

    marker_styles = ["o", "s", "D"]
    dash_styles = ["-", "--"]
    colors = palette

    fig, ax = plt.subplots()
    for im, hue_cat_value in enumerate(hue_cat_values):
        for il, style_cat_value in enumerate(style_cat_values):
            cur_df = df[(df[hue_cat_name] == hue_cat_value) & (df[style_cat_name] == style_cat_value)]
            ax.plot(cur_df[x_name], cur_df[y_name], marker=marker_styles[im], linestyle=dash_styles[il], color=colors[im])

    legend_handles = []

    legend_handles.append(mlines.Line2D([0], [0], linestyle="none", marker="", label=get_title(hue_cat_name)))
    for im, heu_cat_value in enumerate(hue_cat_values):
        handle = mlines.Line2D([], [], color=colors[im], marker=marker_styles[im], label=heu_cat_value)
        legend_handles.append(handle)

    if style_cat_name != hue_cat_name:
        legend_handles.append(mlines.Line2D([0], [0], linestyle="none", marker="", label=get_title(style_cat_name)))
        for il, style_cat_value in enumerate(style_cat_values):
            handle = mlines.Line2D([], [], linestyle=dash_styles[il], color=colors[0], label=style_cat_value)
            legend_handles.append(handle)


    plt.legend(handles=legend_handles)
    plt.ylabel(get_title(y_name))
    plt.xlabel(get_title(x_name))
    plt.xticks(x_values)
    plt.grid(linestyle="--", axis="y", color="grey", linewidth=0.5)

    save_figure(fig, "./images/{}.pdf".format(fig_name))

    # if display:
    plt.show()




def main(args):
    exp_name = args["exp"]

    # if exp_name == "offchain":

    data = find_raw_report_data(exp_name)
    agg_df= aggregate_report_data(exp_name, data)
    modify_data(exp_name, agg_df)

    visualize_data(exp_name, agg_df)
    # # Opening JSON file
    # f = open('data.json')

    # # returns JSON object as
    # # a dictionary
    # data = json.load(f)

    # # Iterating through the json
    # # list
    # for i in data['emp_details']:
    #     print(i)

    # # Closing file
    # f.close()

if __name__ == "__main__":
    args = setup_arguments(add_arguments)
    setup_console_logging(args)
    main(args)
