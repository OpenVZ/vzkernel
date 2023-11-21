// SPDX-License-Identifier: (GPL-2.0-only OR BSD-3-Clause)
//
// This file is provided under a dual BSD/GPLv2 license.  When using or
// redistributing this file, you may do so under either license.
//
// Copyright(c) 2018 Intel Corporation. All rights reserved.
//
// Authors: Keyon Jie <yang.jie@linux.intel.com>
//

#include <sound/pcm_params.h>
#include <sound/hdaudio_ext.h>
#include <sound/intel-nhlt.h>
#include <sound/sof/ipc4/header.h>
#include <uapi/sound/sof/header.h>
#include "../ipc4-priv.h"
#include "../ipc4-topology.h"
#include "../sof-priv.h"
#include "../sof-audio.h"
#include "hda.h"

/*
 * The default method is to fetch NHLT from BIOS. With this parameter set
 * it is possible to override that with NHLT in the SOF topology manifest.
 */
static bool hda_use_tplg_nhlt;
module_param_named(sof_use_tplg_nhlt, hda_use_tplg_nhlt, bool, 0444);
MODULE_PARM_DESC(sof_use_tplg_nhlt, "SOF topology nhlt override");

int hda_dai_config(struct snd_soc_dapm_widget *w, unsigned int flags,
		   struct snd_sof_dai_config_data *data)
{
	struct snd_sof_widget *swidget = w->dobj.private;
	const struct sof_ipc_tplg_ops *tplg_ops;
	struct snd_soc_component *component;
	struct snd_sof_dev *sdev;
	int ret;

	if (!swidget)
		return 0;

	component = swidget->scomp;
	sdev = snd_soc_component_get_drvdata(component);
	tplg_ops = sof_ipc_get_ops(sdev, tplg);

	if (tplg_ops && tplg_ops->dai_config) {
		ret = tplg_ops->dai_config(sdev, swidget, flags, data);
		if (ret < 0) {
			dev_err(sdev->dev, "DAI config with flags %x failed for widget %s\n",
				flags, w->name);
			return ret;
		}
	}

	return 0;
}

#if IS_ENABLED(CONFIG_SND_SOC_SOF_HDA_AUDIO_CODEC)

static const struct hda_dai_widget_dma_ops *
hda_dai_get_ops(struct snd_pcm_substream *substream, struct snd_soc_dai *cpu_dai)
{
	struct snd_soc_dapm_widget *w = snd_soc_dai_get_widget(cpu_dai, substream->stream);
	struct snd_sof_dev *sdev = snd_soc_component_get_drvdata(cpu_dai->component);
	struct snd_sof_widget *swidget = w->dobj.private;
	struct snd_sof_dai *sdai;

	/*
	 * The swidget parameter of hda_select_dai_widget_ops() is ignored in
	 * case of DSPless mode
	 */
	if (sdev->dspless_mode_selected)
		return hda_select_dai_widget_ops(sdev, NULL);

	sdai = swidget->private;

	/* select and set the DAI widget ops if not set already */
	if (!sdai->platform_private) {
		const struct hda_dai_widget_dma_ops *ops =
			hda_select_dai_widget_ops(sdev, swidget);
		if (!ops)
			return NULL;

		/* check if mandatory ops are set */
		if (!ops || !ops->get_hext_stream)
			return NULL;

		sdai->platform_private = ops;
	}

	return sdai->platform_private;
}

static int hda_link_dma_cleanup(struct snd_pcm_substream *substream,
				struct hdac_ext_stream *hext_stream,
				struct snd_soc_dai *cpu_dai,
				struct snd_soc_dai *codec_dai)
{
	struct snd_sof_dev *sdev = snd_soc_component_get_drvdata(cpu_dai->component);
	const struct hda_dai_widget_dma_ops *ops = hda_dai_get_ops(substream, cpu_dai);
	struct hdac_stream *hstream = &hext_stream->hstream;
	struct hdac_bus *bus = hstream->bus;
	struct sof_intel_hda_stream *hda_stream;
	struct hdac_ext_link *hlink;
	int stream_tag;

	hlink = snd_hdac_ext_bus_get_hlink_by_name(bus, codec_dai->component->name);
	if (!hlink)
		return -EINVAL;

	if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK) {
		stream_tag = hdac_stream(hext_stream)->stream_tag;
		snd_hdac_ext_bus_link_clear_stream_id(hlink, stream_tag);
	}

	if (ops->release_hext_stream)
		ops->release_hext_stream(sdev, cpu_dai, substream);

	hext_stream->link_prepared = 0;

	/* free the host DMA channel reserved by hostless streams */
	hda_stream = hstream_to_sof_hda_stream(hext_stream);
	hda_stream->host_reserved = 0;

	return 0;
}

static int hda_link_dma_hw_params(struct snd_pcm_substream *substream,
				  struct snd_pcm_hw_params *params, struct snd_soc_dai *cpu_dai)
{
	const struct hda_dai_widget_dma_ops *ops = hda_dai_get_ops(substream, cpu_dai);
	struct snd_soc_pcm_runtime *rtd = asoc_substream_to_rtd(substream);
	struct snd_soc_dai *codec_dai = asoc_rtd_to_codec(rtd, 0);
	struct hdac_ext_stream *hext_stream;
	struct hdac_stream *hstream;
	struct hdac_ext_link *hlink;
	struct snd_sof_dev *sdev;
	struct hdac_bus *bus;
	unsigned int format_val;
	unsigned int link_bps;
	int stream_tag;

	sdev = snd_soc_component_get_drvdata(cpu_dai->component);
	bus = sof_to_bus(sdev);

	hlink = snd_hdac_ext_bus_get_hlink_by_name(bus, codec_dai->component->name);
	if (!hlink)
		return -EINVAL;

	hext_stream = ops->get_hext_stream(sdev, cpu_dai, substream);

	if (!hext_stream) {
		if (ops->assign_hext_stream)
			hext_stream = ops->assign_hext_stream(sdev, cpu_dai, substream);
	}

	if (!hext_stream)
		return -EBUSY;

	hstream = &hext_stream->hstream;
	stream_tag = hstream->stream_tag;

	if (hext_stream->hstream.direction == SNDRV_PCM_STREAM_PLAYBACK)
		snd_hdac_ext_bus_link_set_stream_id(hlink, stream_tag);

	/* set the hdac_stream in the codec dai */
	snd_soc_dai_set_stream(codec_dai, hdac_stream(hext_stream), substream->stream);

	if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK)
		link_bps = codec_dai->driver->playback.sig_bits;
	else
		link_bps = codec_dai->driver->capture.sig_bits;

	if (ops->reset_hext_stream)
		ops->reset_hext_stream(sdev, hext_stream);

	format_val = snd_hdac_calc_stream_format(params_rate(params), params_channels(params),
						 params_format(params), link_bps, 0);

	dev_dbg(bus->dev, "format_val=%#x, rate=%d, ch=%d, format=%d\n", format_val,
		params_rate(params), params_channels(params), params_format(params));

	if (ops->setup_hext_stream)
		ops->setup_hext_stream(sdev, hext_stream, format_val);

	hext_stream->link_prepared = 1;

	return 0;
}

static int hda_link_dma_prepare(struct snd_pcm_substream *substream, struct snd_soc_dai *cpu_dai)
{
	struct snd_soc_pcm_runtime *rtd = asoc_substream_to_rtd(substream);
	int stream = substream->stream;

	return hda_link_dma_hw_params(substream, &rtd->dpcm[stream].hw_params, cpu_dai);
}

static int hda_dai_hw_free(struct snd_pcm_substream *substream, struct snd_soc_dai *cpu_dai)
{
	struct snd_sof_dev *sdev = snd_soc_component_get_drvdata(cpu_dai->component);
	const struct hda_dai_widget_dma_ops *ops = hda_dai_get_ops(substream, cpu_dai);
	struct snd_soc_pcm_runtime *rtd = asoc_substream_to_rtd(substream);
	struct snd_soc_dai *codec_dai = asoc_rtd_to_codec(rtd, 0);
	struct hdac_ext_stream *hext_stream;

	if (!ops) {
		dev_err(sdev->dev, "DAI widget ops not set\n");
		return -EINVAL;
	}

	hext_stream = ops->get_hext_stream(sdev, cpu_dai, substream);
	if (!hext_stream)
		return 0;

	return hda_link_dma_cleanup(substream, hext_stream, cpu_dai, codec_dai);
}

static int hda_dai_hw_params(struct snd_pcm_substream *substream,
			     struct snd_pcm_hw_params *params,
			     struct snd_soc_dai *dai)
{
	struct snd_soc_dapm_widget *w = snd_soc_dai_get_widget(dai, substream->stream);
	struct snd_sof_dev *sdev = snd_soc_component_get_drvdata(dai->component);
	const struct hda_dai_widget_dma_ops *ops = hda_dai_get_ops(substream, dai);
	struct hdac_ext_stream *hext_stream;
	struct snd_sof_dai_config_data data = { 0 };
	unsigned int flags = SOF_DAI_CONFIG_FLAGS_HW_PARAMS;
	int ret;

	if (!ops) {
		dev_err(sdev->dev, "DAI widget ops not set\n");
		return -EINVAL;
	}

	hext_stream = ops->get_hext_stream(sdev, dai, substream);
	if (hext_stream && hext_stream->link_prepared)
		return 0;

	ret = hda_link_dma_hw_params(substream, params, dai);
	if (ret < 0)
		return ret;

	hext_stream = ops->get_hext_stream(sdev, dai, substream);

	flags |= SOF_DAI_CONFIG_FLAGS_2_STEP_STOP << SOF_DAI_CONFIG_FLAGS_QUIRK_SHIFT;
	data.dai_data = hdac_stream(hext_stream)->stream_tag - 1;

	return hda_dai_config(w, flags, &data);
}

static int hda_dai_prepare(struct snd_pcm_substream *substream, struct snd_soc_dai *dai)
{
	struct snd_soc_dapm_widget *w = snd_soc_dai_get_widget(dai, substream->stream);
	struct snd_sof_dev *sdev = snd_soc_component_get_drvdata(dai->component);
	const struct hda_dai_widget_dma_ops *ops = hda_dai_get_ops(substream, dai);
	struct hdac_ext_stream *hext_stream;
	struct snd_sof_dai_config_data data = { 0 };
	unsigned int flags = SOF_DAI_CONFIG_FLAGS_HW_PARAMS;
	int ret;

	hext_stream = ops->get_hext_stream(sdev, dai, substream);
	if (hext_stream && hext_stream->link_prepared)
		return 0;

	dev_dbg(sdev->dev, "prepare stream dir %d\n", substream->stream);

	ret = hda_link_dma_prepare(substream, dai);
	if (ret < 0)
		return ret;

	hext_stream = ops->get_hext_stream(sdev, dai, substream);

	flags |= SOF_DAI_CONFIG_FLAGS_2_STEP_STOP << SOF_DAI_CONFIG_FLAGS_QUIRK_SHIFT;
	data.dai_data = hdac_stream(hext_stream)->stream_tag - 1;

	return hda_dai_config(w, flags, &data);
}

/*
 * In contrast to IPC3, the dai trigger in IPC4 mixes pipeline state changes
 * (over IPC channel) and DMA state change (direct host register changes).
 */
static int hda_dai_trigger(struct snd_pcm_substream *substream, int cmd, struct snd_soc_dai *dai)
{
	struct snd_sof_dev *sdev = snd_soc_component_get_drvdata(dai->component);
	const struct hda_dai_widget_dma_ops *ops = hda_dai_get_ops(substream, dai);
	struct hdac_ext_stream *hext_stream;
	struct snd_soc_pcm_runtime *rtd;
	struct snd_soc_dai *codec_dai;
	int ret;

	dev_dbg(dai->dev, "cmd=%d dai %s direction %d\n", cmd,
		dai->name, substream->stream);

	hext_stream = ops->get_hext_stream(sdev, dai, substream);
	if (!hext_stream)
		return -EINVAL;

	rtd = asoc_substream_to_rtd(substream);
	codec_dai = asoc_rtd_to_codec(rtd, 0);

	if (ops->pre_trigger) {
		ret = ops->pre_trigger(sdev, dai, substream, cmd);
		if (ret < 0)
			return ret;
	}

	if (ops->trigger) {
		ret = ops->trigger(sdev, dai, substream, cmd);
		if (ret < 0)
			return ret;
	}

	if (ops->post_trigger) {
		ret = ops->post_trigger(sdev, dai, substream, cmd);
		if (ret < 0)
			return ret;
	}

	switch (cmd) {
	case SNDRV_PCM_TRIGGER_SUSPEND:
		ret = hda_link_dma_cleanup(substream, hext_stream, dai, codec_dai);
		if (ret < 0) {
			dev_err(sdev->dev, "%s: failed to clean up link DMA\n", __func__);
			return ret;
		}
		break;
	default:
		break;
	}

	return 0;
}

static const struct snd_soc_dai_ops hda_dai_ops = {
	.hw_params = hda_dai_hw_params,
	.hw_free = hda_dai_hw_free,
	.trigger = hda_dai_trigger,
	.prepare = hda_dai_prepare,
};

static int hda_dai_suspend(struct hdac_bus *bus)
{
	struct snd_soc_pcm_runtime *rtd;
	struct hdac_ext_stream *hext_stream;
	struct hdac_stream *s;
	int ret;

	/* set internal flag for BE */
	list_for_each_entry(s, &bus->stream_list, list) {

		hext_stream = stream_to_hdac_ext_stream(s);

		/*
		 * clear stream. This should already be taken care for running
		 * streams when the SUSPEND trigger is called. But paused
		 * streams do not get suspended, so this needs to be done
		 * explicitly during suspend.
		 */
		if (hext_stream->link_substream) {
			const struct hda_dai_widget_dma_ops *ops;
			struct snd_sof_widget *swidget;
			struct snd_soc_dapm_widget *w;
			struct snd_soc_dai *codec_dai;
			struct snd_soc_dai *cpu_dai;
			struct snd_sof_dev *sdev;
			struct snd_sof_dai *sdai;

			rtd = asoc_substream_to_rtd(hext_stream->link_substream);
			cpu_dai = asoc_rtd_to_cpu(rtd, 0);
			codec_dai = asoc_rtd_to_codec(rtd, 0);
			w = snd_soc_dai_get_widget(cpu_dai, hdac_stream(hext_stream)->direction);
			swidget = w->dobj.private;
			sdev = snd_soc_component_get_drvdata(swidget->scomp);
			sdai = swidget->private;
			ops = sdai->platform_private;

			ret = hda_link_dma_cleanup(hext_stream->link_substream,
						   hext_stream,
						   cpu_dai, codec_dai);
			if (ret < 0)
				return ret;

			/* for consistency with TRIGGER_SUSPEND  */
			if (ops->post_trigger) {
				ret = ops->post_trigger(sdev, cpu_dai,
							hext_stream->link_substream,
							SNDRV_PCM_TRIGGER_SUSPEND);
				if (ret < 0)
					return ret;
			}
		}
	}

	return 0;
}

#endif

void hda_set_dai_drv_ops(struct snd_sof_dev *sdev, struct snd_sof_dsp_ops *ops)
{
	int i;

	for (i = 0; i < ops->num_drv; i++) {
#if IS_ENABLED(CONFIG_SND_SOC_SOF_HDA_AUDIO_CODEC)
		if (strstr(ops->drv[i].name, "iDisp") ||
		    strstr(ops->drv[i].name, "Analog") ||
		    strstr(ops->drv[i].name, "Digital"))
			ops->drv[i].ops = &hda_dai_ops;
#endif
	}

	if (sdev->pdata->ipc_type == SOF_INTEL_IPC4 && !hda_use_tplg_nhlt) {
		struct sof_ipc4_fw_data *ipc4_data = sdev->private;

		ipc4_data->nhlt = intel_nhlt_init(sdev->dev);
	}
}

void hda_ops_free(struct snd_sof_dev *sdev)
{
	if (sdev->pdata->ipc_type == SOF_INTEL_IPC4) {
		struct sof_ipc4_fw_data *ipc4_data = sdev->private;

		if (!hda_use_tplg_nhlt)
			intel_nhlt_free(ipc4_data->nhlt);
	}
}
EXPORT_SYMBOL_NS(hda_ops_free, SND_SOC_SOF_INTEL_HDA_COMMON);

/*
 * common dai driver for skl+ platforms.
 * some products who use this DAI array only physically have a subset of
 * the DAIs, but no harm is done here by adding the whole set.
 */
struct snd_soc_dai_driver skl_dai[] = {
{
	.name = "SSP0 Pin",
	.playback = {
		.channels_min = 1,
		.channels_max = 8,
	},
	.capture = {
		.channels_min = 1,
		.channels_max = 8,
	},
},
{
	.name = "SSP1 Pin",
	.playback = {
		.channels_min = 1,
		.channels_max = 8,
	},
	.capture = {
		.channels_min = 1,
		.channels_max = 8,
	},
},
{
	.name = "SSP2 Pin",
	.playback = {
		.channels_min = 1,
		.channels_max = 8,
	},
	.capture = {
		.channels_min = 1,
		.channels_max = 8,
	},
},
{
	.name = "SSP3 Pin",
	.playback = {
		.channels_min = 1,
		.channels_max = 8,
	},
	.capture = {
		.channels_min = 1,
		.channels_max = 8,
	},
},
{
	.name = "SSP4 Pin",
	.playback = {
		.channels_min = 1,
		.channels_max = 8,
	},
	.capture = {
		.channels_min = 1,
		.channels_max = 8,
	},
},
{
	.name = "SSP5 Pin",
	.playback = {
		.channels_min = 1,
		.channels_max = 8,
	},
	.capture = {
		.channels_min = 1,
		.channels_max = 8,
	},
},
{
	.name = "DMIC01 Pin",
	.capture = {
		.channels_min = 1,
		.channels_max = 4,
	},
},
{
	.name = "DMIC16k Pin",
	.capture = {
		.channels_min = 1,
		.channels_max = 4,
	},
},
#if IS_ENABLED(CONFIG_SND_SOC_SOF_HDA_AUDIO_CODEC)
{
	.name = "iDisp1 Pin",
	.playback = {
		.channels_min = 1,
		.channels_max = 8,
	},
},
{
	.name = "iDisp2 Pin",
	.playback = {
		.channels_min = 1,
		.channels_max = 8,
	},
},
{
	.name = "iDisp3 Pin",
	.playback = {
		.channels_min = 1,
		.channels_max = 8,
	},
},
{
	.name = "iDisp4 Pin",
	.playback = {
		.channels_min = 1,
		.channels_max = 8,
	},
},
{
	.name = "Analog CPU DAI",
	.playback = {
		.channels_min = 1,
		.channels_max = 16,
	},
	.capture = {
		.channels_min = 1,
		.channels_max = 16,
	},
},
{
	.name = "Digital CPU DAI",
	.playback = {
		.channels_min = 1,
		.channels_max = 16,
	},
	.capture = {
		.channels_min = 1,
		.channels_max = 16,
	},
},
{
	.name = "Alt Analog CPU DAI",
	.playback = {
		.channels_min = 1,
		.channels_max = 16,
	},
	.capture = {
		.channels_min = 1,
		.channels_max = 16,
	},
},
#endif
};

int hda_dsp_dais_suspend(struct snd_sof_dev *sdev)
{
	/*
	 * In the corner case where a SUSPEND happens during a PAUSE, the ALSA core
	 * does not throw the TRIGGER_SUSPEND. This leaves the DAIs in an unbalanced state.
	 * Since the component suspend is called last, we can trap this corner case
	 * and force the DAIs to release their resources.
	 */
#if IS_ENABLED(CONFIG_SND_SOC_SOF_HDA_AUDIO_CODEC)
	int ret;

	ret = hda_dai_suspend(sof_to_bus(sdev));
	if (ret < 0)
		return ret;
#endif

	return 0;
}
